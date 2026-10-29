# Distro lifecycle testing

The Incus suite tests the actual Kidobo artifact in disposable QEMU/KVM virtual machines,
including real guest firewall and systemd operations. It supplements local application tests
and static compatibility checks. Publication requires candidate coverage on every required
target before pushing refs or uploading assets, unless the user explicitly selects
`just publish-release X.Y.Z --skip-e2e`. Published-release smoke testing is separate.

## Scope and non-goals

This section is the authoritative scope contract for E2E work. Read it before changing the
runner, guest scripts, launcher, fixtures, image acquisition/monitoring, matrix configuration,
or release integration.

E2E proves that Kidobo installs, accepts configuration, enforces IPv4/IPv6 policy, runs through
systemd and reboot, preserves state through upgrade and expected failures, flushes its own
rules, and uninstalls on the configured distributions. Supporting work is limited to ordinary
guest provisioning, deterministic fixtures, bounded execution, trustworthy results, useful
diagnostics, and cleanup of suite-owned resources.

Supporting image work is limited to acquiring verified, unmodified vendor disks, wrapping them
in Incus metadata, bootstrapping the Incus agent, and reporting available image/distro updates.
Image pins are reviewed changes. Discovery must not automatically adopt images, add or retire
targets, or change required/advisory policy. No background monitoring service is permitted.

The publisher's explicit `--skip-e2e` flag excludes all E2E-specific validation: compilation,
formatting, linting, documentation, harness and launcher tests, E2E integration fixtures, image
operations, and VM execution. It requires no E2E-only tools and performs no E2E cleanup.
Application checks and publication safeguards remain mandatory, including the existing coverage
thresholds. See [publication validation](../scripts/README.md#publication) for retained application
gates and the internal selection recipes.

Keep future E2E-specific packages and targets outside that skip path. The harness lives in
`kidobo-e2e`, and root-package E2E integration targets must be named `e2e_*`. Dedicated E2E
helpers must not be included by non-E2E fixtures or traversed by their formatter inputs; only
neutral fixture utilities may be shared. Package and target selection must exclude E2E from
compilation, not merely filter test names or coverage reports. Default publishing retains its
full scope. `just test` excludes E2E-system tests unless explicitly requested with
`just test --include-e2e`, which runs the full workspace suite without launching the VM matrix.

The harness is not a general VM/image manager, distro-image or bootloader repair tool,
historical-result reuse system, or duplicate of the exhaustive application unit tests. Do not
add orchestration platforms, background services, automatic repair, or fallback systems to
make an environment failure disappear. Report environment failures separately from application
failures; neither justifies weakening assertions.

Kernel compatibility is established by the running kernel's required capabilities and Kidobo's
observed behavior. Kernel freshness, version equality, and boot-default management are non-goals.
A different installed kernel or a version change across reboot is informational, not a warning
or failure. Missing required modules, unavailable firewall backends, and broken enforcement
remain failures. Do not add kernel selection, boot repair, or fallback to hide those failures.

For each proposed addition, identify the Kidobo behavior it proves and why existing coverage
is insufficient. New platforms, scenarios, persistent state, reuse mechanisms, repair/fallback
behavior, and release-policy changes require explicit user scope. Ordinary fixes within the
existing contract do not require renewed permission. Prefer removing unnecessary state and
failure paths over introducing another mechanism around them.

Every selected target gets a fresh VM and repeats OS preparation and application testing on
every run. Repeated work is an accepted cost of a smaller harness. Incus may cache upstream
images normally, including the verified raw vendor images imported into its suite project;
the harness does not publish prepared images or reuse prior test results.
Keep the current matrix and required/advisory policy unless a change is explicitly requested.

Two existing exceptions are bounded rather than precedents for expansion:

- The recognized Incus agent layout receives a guest-only service drop-in restoring its
  executable's `bin_t` label after vendor setup, allowing the configured SELinux-enforcing tests.
  Its bounded relabel/reboot and enforcement checks remain prerequisites; unsupported layouts
  fail that target rather than invoking a new repair path.
- The upgrade fixture recognizes the exact documented Debian 12 failure of baseline versions
  `v0.14.2`/`v0.14.3` with both iptables binaries reporting 1.8.9/nf_tables and the known
  incompatible-chain diagnostic. It verifies preserved state and exercises the candidate
  afterward. This baseline recovery never exempts a candidate or published target from its
  assertions.

Agents must not run the VM matrix without an explicit and express user request. Changes,
reviews, documentation, and local fixture validation do not authorize it. Never exercise the
host's live firewall or systemd. Mutation-test execution also remains the user's responsibility.

## Coverage and outcomes

The required release targets are Debian 12/13 and Ubuntu 24.04/26.04. Publication and
`just e2e-artifact` select those four targets. `just e2e` selects all seven configured targets,
including advisory Fedora 44 and AlmaLinux 9/10. Advisory environment or application failures
remain visible but do not fail the required release gate. Full seven-platform qualification
requires every selected target to pass. A filtered run does not qualify publication.
Acceptance applies to the recorded environment; it does not establish compatibility with every
kernel available for that distribution.

The [matrix configuration](../config/e2e.toml) records package prerequisites and target security
requirements. `required` defaults to `true`; advisory targets explicitly set it to `false`.
Fedora and AlmaLinux require enforcing SELinux; other targets retain their image defaults.

A target's environment or application failure does not suppress other selected targets.
Cancellation, shared infrastructure/reporting failure, or inability to safely release a VM slot
stops new work and triggers cleanup. Required assertions, artifact-integrity checks, saving
authoritative transcripts/results, evidence-archive finalization, and cleanup are mandatory.
Failures in these boundaries cannot qualify a run. Supplemental diagnostic failures are warnings;
they neither erase application failures nor prevent an otherwise valid target from passing.

## Host preparation

Use an x86-64 Linux host with usable `/dev/kvm` and an installed, running Incus server with VM
support. Follow the official [Incus installation guide](https://linuxcontainers.org/incus/docs/main/installing/)
and arrange local daemon access. Setup does not install host packages, change user groups, or
initialize unrelated resources. Release builds need the pinned Rust target, `musl-gcc`, `readelf`,
and `just`. Install host `tar`, plus `genisoimage` or `mkisofs` for the
[agent configuration disk](https://linuxcontainers.org/incus/docs/main/reference/devices_disk/#types-of-disk-devices).
Diagnostic capture uses GNU coreutils `head` and `stdbuf`. Candidate launcher use requires `tmux`.
Image discovery uses `curl`; vendor-image processing also requires `gpg` and `qemu-img`.
The suite never installs these host tools automatically.

After joining `incus-admin`, start a fresh login session. In an existing terminal, a command can
use the new group membership with:

```bash
sg incus-admin -c 'just e2e-setup'
sg incus-admin -c 'just e2e --distro debian-13'
```

Use active group membership for every suite command. The suite creates its own resources;
`incus admin init` is not a prerequisite.

```bash
just e2e-setup
```

Setup owns project/profile `kidobo-e2e`, bridge `kidoboe2e0`, and directory-backed storage pool
`kidobo-e2e`. Conflicting resources fail setup; rerunning setup restores missing owned devices
and applies changed resource settings. The default `max_parallel_vms = 2` permits two running
VMs, each with 2 vCPUs, 4 GiB memory, and a 30 GiB virtual disk; set it to `1` for diagnosis.
Preflight reserves 1 GiB of host headroom, reduces concurrency when needed, and refuses to start
if one guest cannot fit. A coordinator lock prevents competing operations from exceeding limits.
Allow disk space for upstream images, disposable guests, candidate artifacts, and retained logs.

Before a run, ownership-checked recovery removes abandoned suite-owned VMs with valid run names
and absent owner PIDs. Foreign guests, malformed names, and existing owner PIDs block recovery
with a named diagnostic. Explicitly retained guests remain protected and are stopped if necessary.

## Image sources and reviewed updates

Debian and Ubuntu retain their configured Incus aliases. Fedora and AlmaLinux use the exact
vendor cloud images pinned in [the image manifest](../config/e2e-images.toml). Each target in
the matrix has either `image` or `vendor_image`, never both. Vendor pins record the download URL,
SHA-256, architecture, publication date, signing identity, and deterministic Incus fingerprint.

On a missing local fingerprint, the runner downloads the pinned disk, verifies its hash and
qcow2 format, and imports it with deterministic metadata. The vendor disk is not mounted,
converted, provisioned, or repaired during import. A missing or invalid artifact fails that
target; the runner does not substitute another image. Completed imports remain in Incus for
reuse as source images. Every target still creates a fresh VM and repeats all provisioning.

```bash
just e2e-images-check
just e2e-images-refresh
just e2e-images-refresh almalinux-10
```

`e2e-images-check` reports newer vendor builds and stable distro releases without downloading
disks, importing images, editing pins, or starting VMs. It exits successfully when discovery
completes, even if updates are available; incomplete discovery returns nonzero. Every E2E run
also performs this check for all four distro families, including filtered and required-only
runs. Startup discovery has a 30-second total budget. Unavailable or unrecognized metadata
produces an “update status unknown” warning, not a qualification failure. Results are visible
in progress output and retained evidence. No checks happen while E2E is idle.

`e2e-images-refresh` processes one configured vendor target, or all three when omitted. It
verifies vendor-signed checksums with explicitly trusted signing fingerprints in an isolated
keyring, verifies disk hashes and format, generates metadata, and imports the source images.
New pins must satisfy the seven-day publication-age rule; unknown age blocks adoption. Age
uses the later of the official disk's Last-Modified time and the checksum signature timestamp.
Signing-key changes require review. Unsupported architectures and qcow2 backing files are
rejected. The manifest changes atomically only after all requested processing succeeds;
failed processing leaves existing pins and pre-existing images intact. No VM is started.

Review the resulting diff, obtain explicitly authorized fresh lifecycle acceptance for the
affected targets, and then commit the reviewed pins. Source verification or a successful
environment probe is not application acceptance. Run evidence records the exact source hash
and Incus fingerprint independently of bootstrap and application outcomes.

Discovery uses Fedora's release catalogue and official Cloud checksum listings, AlmaLinux's
official release directories and GenericCloud checksums, Debian's stable Release metadata,
and Ubuntu's LTS release feed. Development releases, betas, release candidates, and alternate
architectures are excluded. New major versions are coverage proposals only: adding or retiring
targets, changing Ubuntu's LTS policy, or changing required/advisory status requires explicit
approval. Debian and Ubuntu continue resolving their existing Incus sources normally.

## Guest preparation

Each worker completes one target through creation, provisioning, environment validation,
application tests, diagnostics, and cleanup before taking another target. There is no prepare-all
barrier or parking stage. Preparation resolves an upstream image fingerprint, installs packaged
prerequisites, updates within the pinned distro release, and reboots using the distro's boot
defaults. Ordinary package-manager boot hooks remain in effect; the harness does not select a
kernel or generate initramfs files. Before installing the artifact, it requires successful loading
of `ip_set`, `xt_set`, and `ip_set_hash_net`, working IPv4/IPv6 firewall backends, network readiness,
the requested SELinux mode, and absence of pre-existing Kidobo state. Running kernel versions
before and after preparation and application reboot, plus package inventories, identify what
was tested without imposing version requirements.

Vendor guests receive the agent and cloud-init configuration disks before first boot. Cloud-init
installs the Incus-provided agent and the bounded SELinux label accommodation. Preparation waits
for cloud-init completion and a successful bootstrap status. The identified Fedora hostname-setting
warnings remain visible but do not fail a completed bootstrap; unexpected cloud-init errors,
missing completion, or failed bootstrap prevent application admission.

After the application reboot, the existing timer, service, restored-set, and IPv4/IPv6 traffic
assertions prove that Kidobo restored enforcement. The harness does not preload modules to help
that boot behavior pass; the requested SELinux state must also persist.

AlmaLinux enables EPEL/CRB. SELinux setup retains a bounded readiness deadline, observes completion
of relabeling across boot identities, and requires a saved successful enforcement result plus an
observed enforcing state. The existing Incus-agent label accommodation is described in the scope
contract above. The detached enforcement helper writes output to the system journal and retains
its mandatory completion status and deadline; a failed unit is not treated as pending success.
Missing packages, failed boot, unusable modules, unsupported agent layouts, or
incorrect security state fail the target. The harness does not build replacement dependencies,
rewrite Fedora GRUB/BLS/EFI configuration, or select an automatic fallback environment.

A responsive Incus agent does not establish network connectivity. Guests need an IPv4 lease and
default route, bridge DHCP/DNS, and outbound HTTP/HTTPS for packages and release downloads.
Other host firewall or Docker rules can interfere. Consult the official
[Incus firewall guide](https://linuxcontainers.org/incus/docs/main/howto/network_bridge_firewalld/)
for operator-controlled remedies; the suite never rewrites unrelated host networking.
Read-only inspection commands are:

```bash
incus --project default network show kidoboe2e0
incus --project default network list-leases kidoboe2e0
```

## Run the matrix

`just e2e` starts the build and matrix in a detached `kidobo-e2e` tmux session. A successful
launcher exit means only that the session started. The session survives SSH disconnects and
shows target/stage progress, heartbeats, failures, and final outcomes. Watch it with:

```bash
tmux attach -t kidobo-e2e
```

Detach with **Ctrl+b**, then **d**. The session closes automatically on completion and saves
`output.log` and `exit-status` under the printed `target/e2e/launcher-*/` directory, including
build failures before matrix reporting starts. `KIDOBO_E2E_RESULTS_DIR` also controls this output.
Active sessions prevent competing candidate runs; dead older sessions are archived and removed
automatically. Killing an active session requests interruption. Artifact and published-release
commands run in the foreground.

```bash
just e2e
just e2e --required-only
just e2e --distro debian-12 --keep-failed
just e2e --archive "${RELEASE_ARCHIVE:?set RELEASE_ARCHIVE}" --tag "${RELEASE_TAG:?set RELEASE_TAG}"
just e2e-published
just e2e-published "${RELEASE_TAG:?set RELEASE_TAG}" --distro debian-12
just e2e-artifact "${RELEASE_ARCHIVE:?set RELEASE_ARCHIVE}" "${RELEASE_TAG:?set RELEASE_TAG}"
```

Candidate testing normally builds the static release binary and packages it with the publication
packager in a unique directory under `target/e2e-candidate/<tag>/`. Supplying `--archive ARCHIVE`
(or `--archive=ARCHIVE`) and `--tag TAG` avoids rebuilding but still runs every selected target
from scratch. `just e2e-artifact ARCHIVE TAG` accepts exactly those two arguments and selects
all required targets. No prior success substitutes for a check in the current run.

Each guest serves the frozen archive through a local HTTP fixture and uses the real installer,
including checksum verification, extraction, and replacement. `KIDOBO_RELEASE_BASE_URL` selects
this fixture directory and requires an explicit installer `--version`; ordinary installation
continues to use GitHub. The publisher tests its packaged archive without rebuilding it and
verifies source/artifact identity before publication. Every publisher attempt reruns its gates.
The explicit `--skip-e2e` override skips all E2E-specific validation as defined in the
[scope contract](#scope-and-non-goals), including local harness checks and image operations.
It retains application validation, shared dependency checks, and publication safeguards.

The candidate lane covers initialization, configuration preservation, offline inspection,
IPv4/IPv6 blocked and allowed traffic, safelists, source edits, systemd/timers, reboot recovery,
failure preservation, upgrade, flush, and uninstall. Network namespaces and deterministic HTTP/IRR
fixtures live inside guests. ASN checks execute packaged `bgpq4` against the local fixture.
External IRR availability is outside the gate. Each target retains its installed iptables backend.

Blocked traffic requires both a DROP-rule packet-counter increase and working allowed control
traffic. Paired IPv4/IPv6 probes run concurrently with one-second blocked-connect deadlines.
The expected-check manifest rejects missing, duplicate, unsuccessful, unstarted, or unexpected
assertions; process exit status alone cannot establish success.

The published lane resolves `latest` once and installs genuine GitHub assets, then tests
initialization, configuration, doctor, synchronization, flush, and uninstall. It uses the same
fresh provisioning, but omits candidate post-install reboot and upgrade scenarios. It runs
independently of publication. Immutable old releases cannot validate candidate fixes.

## Diagnose and clean up

Results live under `target/e2e/<run-id>/`; `KIDOBO_E2E_RESULTS_DIR` selects another root.
Publication writes into the original checkout so evidence survives temporary-worktree removal.
Start with `summary.txt`, then follow the target-specific paths and line references:

| Path | Contents |
| --- | --- |
| `summary.txt` | Run identity, coverage, per-target outcomes, and diagnostic warnings |
| `transcript.log` | Coordinator progress and outcomes |
| `results.json` | Aggregate structured results |
| `targets/<distro>/transcript.log` | Full command, stdout/stderr, exit status, and assertion evidence for that target |
| `targets/<distro>/results.json` | Target-local commands, checks, and stages |
| `evidence.tar.gz` | Frozen inputs and available supplemental diagnostics |
| `ownership.json` | Ownership records for safe cleanup |

Command/check identifiers and transcript line numbers are local to each target. Concurrent output
is not merged into one global command history. Full logs remain directly accessible after archive
finalization. For detailed live output, tail the selected target's log:

```bash
run_dir=target/e2e/RUN_ID
tail -f "$run_dir/targets/debian-12/transcript.log"
```

Supplemental boot snapshots, console/QEMU logs, journals, and guest-state captures are bounded
and best-effort. Missing files, dangling symlinks, unsupported tools, timeouts, truncation, and
capture errors remain visible warnings. Collection continues where possible and does not restart
a stopped guest solely to obtain diagnostics. Required environment/application assertions still
fail normally; a warning never hides a failed assertion. Failure to save authoritative logs/results,
finalize the evidence archive, or clean resources remains fatal.

Frozen installer, guest scripts, configuration, image manifest, bootstrap input, metadata,
verification evidence, and hashes are retained in the archive;
candidate bytes and checksums are under `inputs/release/`. Upgrade checks capture the baseline
archive, installer, and checksum manifest, create state with the baseline binary, and verify
preservation and offline operation after candidate installation. The narrow historical baseline
recovery remains explicit in evidence. Inspect archived files without unpacking the whole archive:

```bash
tar -tzf "$run_dir/evidence.tar.gz"
tar -xOf "$run_dir/evidence.tar.gz" ./inputs/SHA256.json
```

Working evidence stays in `.evidence/` until archive creation succeeds. On failure or abrupt
termination, preserve that directory for diagnosis. Historical reports are left untouched and
provide historical evidence only; they do not qualify the current artifact or harness.

VMs are deleted by default. `--keep-failed` retains failed guests and stops them so they do not
consume a running-VM slot. SIGINT, SIGTERM, and SIGHUP request cancellation and cleanup; one
cleanup failure does not prevent attempts for other owned guests. Forced termination or host
shutdown cannot run cleanup, so the next run recovers abandoned guests under the ownership rules.
Logs and evidence remain on disk. Explicit cleanup is also available:

```bash
just e2e-clean RUN_ID
```

Use the same results root and active Incus group membership. Cleanup validates suite ownership and
run identity; never remove the shared project, bridge, or pool to clean one run.

### Retained vendor source images

Completed vendor imports are intentionally retained. There are no prepared-image generations,
automatic pruning, or historical-result reuse. To reclaim an unused source image, inspect its
exact fingerprint and all suite instances:

```bash
incus --project kidobo-e2e image list
incus --project kidobo-e2e image show "${IMAGE_FINGERPRINT:?set IMAGE_FINGERPRINT}"
incus --project kidobo-e2e list --format=json
```

Require the `user.kidobo-e2e-source: kidobo-e2e-v1` property and verify that no running, stopped,
or deliberately retained guest references the fingerprint as `volatile.base_image`. Preserve
foreign, ambiguous, and referenced images. Only then remove that individual image with
`incus --project kidobo-e2e image delete FINGERPRINT`. Deleting a still-pinned, unused source
causes its next run to download and verify it again. Never delete the project or storage pool
to reclaim one image.

### Legacy prepared-image storage

Legacy prepared images are unused and are not automatically deleted. To reclaim their storage,
first inspect images and all instances in the suite project:

```bash
incus --project kidobo-e2e image list
incus --project kidobo-e2e list --format=json
incus --project kidobo-e2e image show "${IMAGE_FINGERPRINT:?set IMAGE_FINGERPRINT}"
```

Only consider an exact fingerprint with `user.kidobo-e2e: kidobo-e2e-v1` and the old
`kidobo_e2e_generation`/`kidobo_e2e_target` preparation properties. Confirm no running, stopped,
or deliberately retained instance references that fingerprint as `volatile.base_image`.
Preserve foreign, ambiguous, or referenced images. After those checks, the operator may remove
that individual unused image with `incus --project kidobo-e2e image delete FINGERPRINT`.
Do not delete all images, the project, or the storage pool.

## Harness organization

The private `kidobo-e2e` crate keeps process mechanics separate from qualification policy:

- `process` owns file-backed command capture, bounded output draining, deadlines, cancellation,
  and child cleanup. Its fallible event callback carries output, heartbeats, and byte counts to
  the runner; the runner owns command records and guest-check validation.
- `matrix` owns worker scheduling and target finalization, including diagnostics and cleanup.
  `matrix::outcome` computes coverage, warnings, platform summaries, and release-gate decisions
  without performing I/O.
- `evidence` owns the guest-input inventory, frozen snapshots, harness identity, and verified
  archive publication. The harness digest includes sorted Rust source paths and contents,
  including test sources, plus the lockfile and toolchain file.

`scripts/e2e/lifecycle.sh` retains guest guards, state, tracing, traps, and phase dispatch.
Function-only helpers under `scripts/e2e/lib/` separate reporting, fixture processes,
network probes, runtime assertions, and upgrade checks. Sourcing a helper performs no guest
operations; local tests load these same definitions with explicit fixture state and fake commands.
FD 9 carries tracing and check markers separately from captured stdout and diagnostics;
background fixtures close it so they cannot keep the execution connection open.

Every helper must appear in the evidence module's guest-input inventory. Snapshotting copies
and hashes these files beneath `inputs/lib/`; lifecycle uploads use those frozen copies at
`/opt/kidobo-e2e/lib/`, never the live checkout. Preparation scripts remain independent of these
helpers. Inventory and fake-Incus tests verify that the complete bundle reaches each guest
before lifecycle execution.

## Validate a harness change

Read the scope contract first. Use local fake-Incus and isolated script fixtures through
`just test --include-e2e`, then the required local gates in the [development guide](development.md#toolchain-and-validation).
`just ci` excludes infrastructure tests and does not establish VM acceptance. Local fixtures use
fake privileged commands, temporary roots, and loopback services; they require Bash, curl,
Python 3, GNU tar/coreutils, and GPG for isolated signature verification. Do not replace missing
real-VM acceptance with a claim based on fixtures.

Real VM acceptance requires a separate, explicit user request. It should cover fresh execution
of the selected targets, configured SELinux modes and observed backends, application assertions,
retained logs, interruption/cleanup, and independent required/all-selected outcomes. Record actual
wall time without summing overlapping target durations; build/packaging time is outside runner time.
Prepared-image and result reuse are outside scope. The separate Debian 11/Alpine gate checks static
binary startup and offline lookup, not full firewall/systemd behavior on those platforms.
