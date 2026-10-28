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
  `v0.14.2`/`v0.14.3`, verifies preserved state, and exercises the candidate afterward. This
  historical baseline recovery never exempts a candidate or published target from its assertions.

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
openSUSE Leap 16.0 remains outside the matrix because packaged `bgpq4` was unavailable.
Reintroducing it requires explicit scope and a passing lifecycle with packaged prerequisites.

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
The explicit `--skip-e2e` override skips only the matrix and its Incus/ISO prerequisites.

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

Old prepared images are unused after this simplification and are not automatically migrated or
deleted. To reclaim their storage, first inspect images and all instances in the suite project:

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
Do not delete all images, the project, or the storage pool. No new cleanup command or automatic
image-management policy is introduced.

## Validate a harness change

Read the scope contract first. Use local fake-Incus and isolated script fixtures through
`just test`, then the required local gates in the [development guide](development.md#toolchain-and-validation).
`just ci` excludes infrastructure tests and does not establish VM acceptance. Local fixtures use
fake privileged commands, temporary roots, and loopback services; they require Bash, curl,
Python 3, GNU tar/coreutils, and GPG for isolated signature verification. Do not replace missing
real-VM acceptance with a claim based on fixtures.

Real VM acceptance requires a separate, explicit user request. It should cover fresh execution
of the selected targets, configured SELinux modes and observed backends, application assertions,
retained logs, interruption/cleanup, and independent required/all-selected outcomes. Record actual
wall time without summing overlapping target durations; build/packaging time is outside runner time.
No cold/warm or resume qualification remains. The separate Debian 11/Alpine gate checks static
binary startup and offline lookup, not full firewall/systemd behavior on those platforms.

## Historical validation evidence

The dated records below describe earlier harness versions and their captured inputs. They are
retained for diagnosis and do not establish acceptance of the current implementation or artifact.

## Initial validation: 22 October 2026

Both eight-target runs completed for version `v0.14.3` after host Incus access, networking,
and ISO tooling were configured. Both exited with status 1: candidate run
`run-1792703914-558810` recorded five passes and three failures; published smoke run
`run-1792703913-557732` recorded six passes and two failures. These historical eight-target
results did not satisfy publication; the current seven-target matrix and subsequent fixes
require fresh validation.

| Target | Candidate lifecycle | Published smoke |
| --- | --- | --- |
| Debian 12 | Application failure, 45.4 s | Application failure, 41.7 s |
| Debian 13 | PASS, 247.6 s | PASS, 74.3 s |
| Ubuntu 24.04 | PASS, 251.7 s | PASS, 76.5 s |
| Ubuntu 26.04 | PASS, 263.2 s | PASS, 84.3 s |
| Fedora 44 | PASS, 306.1 s | PASS, 112.7 s |
| AlmaLinux 9 | Fixture failure, 295.5 s | PASS, 109.0 s |
| AlmaLinux 10 | PASS, 304.6 s | PASS, 109.1 s |
| openSUSE Leap 16.0 | Provisioning failure, 32.6 s | Provisioning failure, 28.6 s |

Debian 12 exposed an application compatibility issue: iptables 1.8.9 with the nftables
backend reports an absent chain using an incompatible-chain diagnostic. The same message
was reproduced with a fresh unrelated absent chain. The subsequent fix handles that exact
requested-chain/filter-table diagnostic and exit status 1 by inspecting a bounded, read-only
chain listing from the same address family. Only absence of the exact chain declaration
establishes that the chain is missing; a listed chain preserves the original error, and a
failed listing propagates its error. The application matches the diagnostic rather than
hard-coding a distro or version.

Upgrade baselines `v0.14.2` and `v0.14.3` require a narrowly guarded harness recovery for
this historical defect on Debian 12 with both iptables binaries reporting 1.8.9/nf_tables
and the exact known error. This recovery applies only to the older upgrade baseline; it does
not mask candidate or published-target failures. Leap's missing packaged `bgpq4` remains a
recorded provisioning failure, with reintroduction deferred as described above.

AlmaLinux 9's full candidate attempt failed when its traffic fixture lost an interface
address and could not bind (`EADDRNOTAVAIL`). The fixture now excludes only its test veth
interface from NetworkManager management before assigning addresses, following the
[scoped NetworkManager device guidance](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/configuring_and_managing_networking/configuring-networkmanager-to-ignore-certain-devices_configuring-and-managing-networking).
It preserves the guest's main network interface and global NetworkManager configuration.
The latest focused AlmaLinux 9 candidate run, `run-1792706036-603679`, passed in 300.5 s.
Its diagnostics retained the test interface address/local route and recorded that the device
was unmanaged. The VM was cleaned up. This focused pass validates the fixture correction;
the original full-matrix failure remains recorded in the table.

The full runs used their captured `inputs/` snapshots. Later custom-configuration repeat-init
and failed-uninstall timer-ordering assertions passed in a focused Debian 13 candidate run,
`run-1792704567-575487`, in 248.5 s. These focused changes do not retroactively alter the
full-matrix results. The earlier full candidate attempt `run-1792700407-470030` exposed
harness assertions that were corrected; it is not a successful matrix result.

Per-target elapsed values include provisioning, application checks, diagnostics, and cleanup.
Their sums are 1,746.8 s for the candidate run and 636.1 s for published smoke; these exclude
host builds, setup, and initial release/baseline resolution. The lanes overlapped in time and
the host image cache was populated, so these observations are not performance benchmarks or
cold-download estimates. Retained evidence records exact image fingerprints, package updates,
kernel versions, and iptables backends.

The tested images included both legacy and nftables iptables backends. Fedora and both
AlmaLinux images reported SELinux Disabled; the suite preserved their image settings.
Enforcing SELinux was not validated. These observations describe the Incus images used,
rather than installations from each distribution's standard ISO.

`just ci` and `just coverage` passed locally. Coverage was 92.53% of regions, 93.65% of
functions, and 93.02% of lines with the existing thresholds. These checks do not establish
VM matrix acceptance.

## Repair validation: 22 October 2026

Two fresh focused candidate runs passed after the Debian chain-detection fix and final
fixture corrections:

| Target | Run | Result | Elapsed |
| --- | --- | --- | --- |
| Debian 12 | `run-1792709120-639527` | PASS; no diagnostic collection failures | 239.6 s |
| AlmaLinux 9 | `run-1792709366-657973` | PASS; no diagnostic collection failures | 297.3 s |

Debian 12 reproduced the known `v0.14.2` baseline synchronization failure with exit status 1
and its exact incompatible-chain diagnostic before the guarded historical recovery. The
corrected candidate then passed its lifecycle. AlmaLinux 9's final network diagnostics
recorded the test veth as unmanaged and retained both assigned address families. Both VMs
were deleted after diagnostic collection.

The Debian candidate archive SHA-256 was
`8f78dbe8fc7eeffcaf44354a6f2f19b498e36654864af1131bf7533f68b7fbfc`;
the AlmaLinux candidate archive SHA-256 was
`8f84346d9c117fcd03da559879d18462e21afe3b6a8a358c378ec031948eddae`.
The differing archives belong to separate captured runs; neither focused result establishes
a complete mandatory-matrix pass.

Local `just ci`, `just coverage`, `just exercise-release`, `just release-compat`, and
`just rustdoc` passed. Coverage was 92.61% of regions, 93.69% of functions, and 93.10% of
lines with the existing thresholds. Release-note generation added the compatibility entry
to `CHANGELOG.md`; the normal check initially reported the intentional unstaged note and
changelog differences. Verification against an isolated temporary index passed without
changing the real staging area, and the final check rewrote no files.

At the time of this record, the seven-target candidate run `run-1792709674-661101` was still
in progress. This record does not establish its completion or corrected-release published smoke.
