# Distro lifecycle testing

The Incus suite installs and operates Kidobo in disposable QEMU/KVM virtual machines,
including real guest firewall and systemd operations. It supplements `just ci` and the
Debian/Alpine static compatibility checks. Publication requires successful candidate coverage for
every required target before any release push or upload; published-release smoke testing is separate.
`just publish-release X.Y.Z --skip-e2e` omits the matrix and its Incus/agent-ISO prerequisites;
all other release checks remain enabled. See the [command reference](../scripts/README.md).
`just ci` keeps its existing local checks and does not launch VMs.

The default release gate has four required targets: Debian 12 and 13, and Ubuntu 24.04 and 26.04.
Publication and `just e2e-artifact` select only required targets, avoiding the runtime cost of
additional compatibility coverage. Run `just e2e` separately to cover all seven configured targets,
including advisory Fedora 44 and AlmaLinux 9 and 10. In that broader run, advisory prerequisite
and application failures are reported without failing the run when every required target passes.
Cleanup failures and shared infrastructure or evidence archive failures still block the run.
Reports distinguish required release-gate success from success on every selected target; full
seven-platform qualification requires every selected target to pass.
In [the matrix configuration](../config/e2e.toml), `required` defaults to `true`; advisory targets
explicitly set `required = false`. Changing this policy changes release coverage and should be
reviewed accordingly. The explicit publisher option `--skip-e2e` omits the entire release matrix.

openSUSE Leap 16.0 is deferred because its configured repositories did not provide the
required `bgpq4` package. Zypper provisioning remains available for future use. Reintroduce
Leap only after verifying an appropriate packaged prerequisite repository and completing a
passing lifecycle run; its earlier failed results remain below.

## Host preparation

Use an x86-64 Linux host with hardware virtualization enabled, usable `/dev/kvm`, and an
installed, running Incus server with VM support. Follow the official
[Incus installation guide](https://linuxcontainers.org/incus/docs/main/installing/) for your
host distribution and arrange access to its local daemon. The setup command does not install
host packages, change user groups, or initialize unrelated Incus resources. Release builds
also need the repository's pinned Rust target, `musl-gcc`, `readelf`, and `just`.

Install `tar` on the host to package retained evidence, and `genisoimage` or `mkisofs`
to generate the agent configuration ISO. Bounded diagnostic capture uses GNU coreutils
`head` and `stdbuf`; unbuffered capture retains short partial output on timeout or interruption.
Every test VM attaches an
[Incus `agent:config` disk](https://linuxcontainers.org/incus/docs/main/reference/devices_disk/#types-of-disk-devices),
which supplies the guest agent when the kernel cannot load it through `9p`. Setup and run
commands fail before launching VMs if neither ISO utility is available; cleanup remains
available without them.

After an administrator adds your account to `incus-admin`, start a fresh login session so
commands inherit that membership. For an existing terminal, run a command with the newly
available group:

```bash
sg incus-admin -c 'just e2e-setup'
sg incus-admin -c 'just e2e --distro debian-13'
```

Use a session with active group membership for every suite command, including cleanup.
The suite creates its own resources; running `incus admin init` is not a prerequisite.

```bash
just e2e-setup
```

Setup creates suite-owned project/profile `kidobo-e2e`, NAT bridge `kidoboe2e0`, and
directory-backed storage pool `kidobo-e2e`. Existing resources must belong to the suite;
conflicts fail setup. Rerunning setup restores missing owned profile devices and applies
changed device/resource settings; an unchanged owned profile is left untouched. Review
[the matrix configuration](../config/e2e.toml) for image selectors
and resource settings. The default `max_parallel_vms = 2` allows two running VMs, each with 2 vCPUs,
4 GiB memory, and a 30 GiB virtual disk. Set it to `1` for diagnosis or comparisons.
Preflight reserves 1 GiB of host memory beyond the guests, reduces concurrency to one when
necessary, and fails before creating guests if one cannot fit. Existing guests in the suite
project are checked before a new matrix. Under the coordinator lock, the runner removes abandoned
suite-owned guests, including leftovers whose old ownership files are missing. It requires a valid
run name and an absent owner PID; foreign guests, malformed names, or an existing owner PID block
recovery with a named diagnostic. Explicitly retained guests are preserved and stopped if needed.
A host-wide coordinator lock
for the local Incus server/project prevents competing operations from racing cache maintenance
or exceeding the configured limit. Allow disk space for pending targets, prepared images, upstream
images, and failure artifacts. Incus images and distro repositories require
network access when preparing images.

The runner admits prerequisites for all pending targets before starting application lifecycles.
A target receives a fresh clone of a compatible prepared image, or builds a new prepared image
when needed. Preparation installs packaged prerequisites, updates each distro within its pinned
release line, selects and reboots into the intended installed kernel, and verifies its required
firewall modules and backends. Every clone repeats kernel, module, network, security-state, and
pristine-application-state checks. The final prepared batch can proceed directly to application
checks without an unnecessary stop/start cycle.

AlmaLinux enables EPEL/CRB. Fedora and AlmaLinux application lifecycles run under enforcing
SELinux; preparation safely relabels previously disabled images before enforcement. A required
target's package, image, kernel, or admission failure stops the application batch, while diagnostics
and cleanup still run. An advisory prerequisite failure leaves successful targets eligible to
continue. The suite requires packaged prerequisites and does not build replacements for unavailable
packages. Resume can reuse compatible successful targets without creating VMs for them.

Relabel readiness requires a boot after the recorded relabel boot, not just a missing
`/.autorelabel` marker. Preparation uses a bounded readiness deadline and verifies a stable boot
identity before proceeding. For the recognized Incus agent layout, a guest-only service drop-in
applies the [upstream `bin_t` executable type](https://github.com/lxc/incus/blob/main/internal/server/instance/drivers/agent-loader/install-linux.sh)
after the vendor agent setup recreates its runtime
files. The existing coreutils tools supply this operation; no extra guest package is needed.
Enforcement runs in a detached guest systemd job so an agent reconnect cannot lose its result.
Admission requires the saved successful result and an observed enforcing state.

## Prepared-image reuse

The suite stores private prepared images in its owned Incus project. Each reusable generation is
created before installing Kidobo and contains no candidate archives, application data, active
fixtures, or previous application results. Instance identity is sanitized before publication and
clone admission verifies the running kernel, required modules, networking, security state, and
absence of Kidobo state. A cache hit changes OS preparation only; application checks still run.
Set `prepared_images.enabled` to `false` to prepare every disposable VM afresh without publishing or reusing prepared images.

The `[prepared_images]` settings in `config/e2e.toml` default to:

| Setting | Default | Behavior |
| --- | --- | --- |
| `enabled` | `true` | Reuse verified preparation generations. |
| `max_age_hours` | `168` | Refresh after seven days from successful preparation; hits do not extend this deadline. |
| `max_generations` | `2` | Retain two unused completed generations per target; generations referenced by retained guests are protected. |
| `prune_after_hours` | `336` | Prune unused generations after fourteen days. |

Preparation code, the host validation contract, prerequisite packages, target and VM resource/profile
definitions, architecture, or SELinux requirements changing invalidates an image immediately.
Upstream image changes alone do not invalidate a generation within its freshness window. A refresh resolves the current upstream
fingerprint and installs current distro packages. Reports retain the preparation time, packages,
kernel, security state, image identity, and verification evidence.

A refresh failure never falls back to expired images. Rejected clone admission invalidates its
generation and permits one fresh rebuild; the rejected attempt remains diagnostic evidence.
Interrupted or incomplete publication never makes a generation reusable. Pruning checks ownership
and usage and does not remove unrelated images or active generations. Maintenance happens during
suite commands; there is no background scheduler.

Force rebuilding preparation images and rerunning every selected target with:

```bash
just e2e --refresh-images
just e2e-artifact "${RELEASE_ARCHIVE:?set RELEASE_ARCHIVE}" "${RELEASE_TAG:?set RELEASE_TAG}" --refresh-images
just e2e-resume RUN_ID --required-only --refresh-images
just publish-release X.Y.Z --refresh-e2e-images
```

Forced refresh also reruns targets that would otherwise qualify for resume. Publisher resume may
still reuse the identical archive and completed local validation with
`--resume-e2e RUN_ID --refresh-e2e-images`. The refresh publisher option cannot combine with
`--skip-e2e`.

## Guest network prerequisites

A responsive Incus agent does not establish guest network connectivity. Before attributing
package download failures to a distro, verify that its VM has an IPv4 lease and default
route. The managed bridge supplies DHCP and DNS through dnsmasq; other host firewall or
Docker rules can interfere with DHCP, DNS, or forwarding. The bridge needs guest access
to its DHCP (UDP 67) and DNS (UDP/TCP 53) services, plus outbound forwarded HTTP/HTTPS
(TCP 80/443) for distro repositories and release downloads. See the official
[Incus firewall guide](https://linuxcontainers.org/incus/docs/main/howto/network_bridge_firewalld/)
for diagnosis and operator-controlled remedies. The test suite does not rewrite unrelated
host firewall or Docker configuration.

These commands inspect the suite's network without changing it:

```bash
incus --project default network show kidoboe2e0
incus --project default network list-leases kidoboe2e0
```

## Run the matrix

`just e2e` requires `tmux` and starts a detached `kidobo-e2e` session before building
the candidate, so the build and matrix survive an SSH disconnect. The command returns
after starting the session; its success does not mean the matrix passed. Watch it with:

```bash
tmux attach -t kidobo-e2e
```

Detach with **Ctrl+b**, then **d**. Reattach with the same command after reconnecting.
The session closes automatically after success or failure. The launcher prints a unique
`target/e2e/launcher-*/` directory containing `output.log` and `exit-status`, including
build failures before a matrix report exists. `KIDOBO_E2E_RESULTS_DIR` also controls these logs.
An active session prevents another candidate run. Completed sessions left by older launchers
are archived under `recovered-session-*/` and removed automatically before starting a new run.
Killing a session while the matrix is active interrupts it. Artifact and published-release
recipes continue to run in the foreground.

```bash
just e2e
just e2e --required-only
just e2e --distro debian-12 --keep-failed
just e2e-published
just e2e-published "${RELEASE_TAG:?set RELEASE_TAG to a published tag}" --distro debian-12
```

By default, candidate testing builds the static release binary and uses the same archive packager
as publication. `just e2e` writes each archive into a new directory under
`target/e2e-candidate/<tag>/`; concurrent invocations do not overwrite each other. Each
guest serves the captured archive through a local HTTP fixture and runs the real
installer, including checksums, extraction, and binary replacement. The installer variable
`KIDOBO_RELEASE_BASE_URL` selects this release directory and requires an explicit `--version`;
normal installation continues to download from GitHub. To test an existing archive without
rebuilding or repackaging it, use `just e2e --archive ARCHIVE --tag TAG`. This retains detached
tmux execution and selects all configured targets unless `--required-only` is supplied. The
`--archive=ARCHIVE` spelling is also accepted.

The candidate lane covers initialization, preserved configuration, offline inspection,
IPv4/IPv6 blocked and allowed traffic, safelists, source edits, systemd/timer execution,
reboot recovery, failure preservation, upgrade, flush, and uninstall. Probes use network
namespaces inside guests; host firewall commands are never test targets. Each distro keeps
its installed iptables backend. The expected SELinux mode is explicit per target, with
`selinux = "enforcing"` on Fedora and AlmaLinux and `"image-default"` elsewhere. HTTP and local
IRR fixtures make source data deterministic; external IRR availability is outside the gate.
ASN checks execute the actual packaged `bgpq4` with only its server endpoint redirected to the
local fixture. They cover both families, source persistence, sync boundaries, and offline caches.

Traffic assertions distinguish a connection timeout from fixture or infrastructure failures.
Blocked traffic requires a DROP-rule packet-counter increase and working allowed control traffic.
Paired IPv4/IPv6 probes use one-second blocked-connect deadlines and run concurrently. A shared,
versioned check manifest requires every phase's expected checks to complete; missing markers,
unstarted planned checks, duplicate outcomes, and unexpected check IDs cannot qualify a phase.

The published lane resolves `latest` once and installs the selected release from genuine
GitHub assets, then tests initialization, configuration, doctor, synchronization, and
uninstall. Its guests use the same prepared-image freshness and clone-admission rules as candidates.
This smoke lane omits the candidate's post-install reboot and upgrade scenarios. It requires
GitHub access and runs independently of publication.

Published `v0.14.3` assets are immutable and still reproduce the Debian 12 missing-chain
failure recorded below. They cannot validate the subsequent candidate fix. After publishing
a corrected release through the candidate gate, run `just e2e-published <corrected-tag>`
as a separate post-publication smoke milestone across the configured targets.

For an existing release archive, including publisher use:

```bash
release_tag="${RELEASE_TAG:?set RELEASE_TAG to the packaged candidate tag}"
release_archive="${RELEASE_ARCHIVE:?set RELEASE_ARCHIVE to the existing tar.gz path}"
just e2e-artifact "${release_archive}" "${release_tag}"
```

This command selects every configured required target and excludes advisory targets. It accepts
optional `--resume RUN_ID` and `--refresh-images` arguments, in either order; selecting an individual
distro cannot bypass the release gate.
A filtered diagnosis alone does not satisfy publication; every required target needs a compatible
successful lifecycle result. The underlying runner's `--required-only` option selects required
targets, and the report records that selection.
The publisher's `--skip-e2e` option is a deliberate release-workflow override; it does not change
these candidate or artifact commands or make a prior matrix run count for the skipped release.

## Resume a candidate

After correcting a failed target's environment, resume against the same captured candidate.
Select only required coverage for the release gate, or include advisory compatibility targets:

```bash
just e2e-resume RUN_ID --required-only
just e2e-resume RUN_ID
```

This foreground command reads the candidate archive and tag from the prior run's retained
evidence. It creates a new run and leaves the earlier report and archive intact. Without
`--required-only`, it selects all seven configured targets. Compatible successful selected targets
are reused; failed, incomplete, new, or incompatible selected targets get fresh VMs. The new report
identifies reused results and their source run. If you already have the exact candidate archive
and tag, the artifact command resumes required coverage:

```bash
just e2e-artifact "${release_archive}" "${release_tag}" --resume RUN_ID
```

Reuse requires the exact candidate archive hash and tag, matching installer and guest-script
hashes and validation contract, matching target and VM resource definitions, and the same upgrade
baseline tag, archive, installer, and checksum manifest. Preparation provenance must remain within
the seven-day freshness limit. A reused target must have completed the full candidate lifecycle with
successful stages, diagnostics, and cleanup. Changes to a target's definition or VM resources
invalidate that target's earlier success. A changed candidate, installer, guest script, or checksum
manifest rejects resume and requires a fresh run for all targets.
Published smoke results cannot substitute for candidate lifecycle coverage.

Historical reports remain readable, but evidence predating the current validation contract cannot
qualify the strengthened checks. Resume verifies the source evidence archive's recorded SHA-256
before using it.
Keep source runs and evidence when preserving a chain of resumed results.

For a failed publication attempt created with resume support, use:

```bash
just publish-release X.Y.Z --resume-e2e RUN_ID
```

The publisher retains the exact candidate archive and validation identity under
`target/release-artifacts/<tag>/` when the matrix fails. It checks the source commit,
reconstructed candidate tree and saved release date, and artifact hashes before reusing completed
local validation and resuming E2E against that archive. It does not rebuild or repackage the
candidate on resume. Source or candidate changes require a fresh publication attempt. First move
the retained candidate directory aside, preserving it for inspection, because a fresh attempt
refuses to overwrite an existing candidate:

```bash
release_tag="${RELEASE_TAG:?set RELEASE_TAG to vX.Y.Z}"
candidate_dir="target/release-artifacts/${release_tag}"
saved_dir="$(mktemp -d "target/release-artifacts/${release_tag}-saved-XXXXXXXX")"
mv "${candidate_dir}" "${saved_dir}/candidate"
just publish-release "${release_tag}"
```

`--resume-e2e` and `--skip-e2e` are mutually exclusive. `--refresh-e2e-images` can combine with
resume, but cannot combine with `--skip-e2e`. Older publisher attempts without retained
validation metadata cannot use publisher resume, even if their evidence remains eligible for
`just e2e-resume`.

## Diagnose and clean up

Results live under `target/e2e/<run-id>/` by default. Set `KIDOBO_E2E_RESULTS_DIR` to
select another results root. Publication selects the original checkout's results root so logs
survive removal of its temporary worktree. The run ID is the results directory name and
instance-name prefix printed when each fresh VM starts. The terminal streams the complete
chronological transcript by default, with named distro/stage boundaries, command arguments,
stdout/stderr labels, exit statuses, and elapsed time. Silent commands print a heartbeat
every 15 seconds. Guest checks show their expectations and observations, including traffic
probe outcomes, preserved-state comparisons, expected failures, and known baseline recovery.

Completed runs contain at most five top-level files:

| File | Read it for |
| --- | --- |
| `summary.txt` | Run identity, coverage, outcomes, warnings, and transcript line references |
| `transcript.log` | Full chronological command, output, and check evidence, matching the terminal |
| `results.json` | Structured distro, command, and check records |
| `evidence.tar.gz` | Frozen inputs, hashes, raw guest diagnostics, and snapshots |
| `ownership.json` | Resource ownership needed to retry cleanup safely |

Start with the summary, then follow its transcript line references to review what happened.
The summary updates during execution; later checks remain not-run until they begin. Follow
the same transcript from a second terminal, substituting the printed run ID:

```bash
run_dir=target/e2e/RUN_ID
tail -f "$run_dir/transcript.log"
```

The transcript preserves ordering within each output stream; ordering between stdout and
stderr reflects when the coordinator observed the output. Concurrent targets have explicit command
and stage identities and may interleave. Shell tracing includes script, function, and line context
and uses a separate descriptor so captured command results remain intact.

Background fixtures close the tracing descriptor as well as redirecting stdout/stderr.
Otherwise the fixture can keep an Incus exec stream open after the lifecycle shell exits,
consuming the entire 600-second phase timeout even when every assertion passed.
Local fixture HTTP probes bypass proxies and have one-second request limits within a
five-second startup deadline. The source fixture uses content ETags so feed rewrites do
not need timestamp-resolution sleeps; unchanged content still exercises HTTP 304 responses.
OS upgrades reuse the package metadata refreshed during prerequisite provisioning.
Temporary timer deferral resets inherited triggers before setting a delay relative to timer
activation, preventing the normal boot trigger from racing configuration changes.
The candidate's post-install reboot still tests the generated two-minute boot timer;
that wait remains part of every candidate lifecycle. Package updates run during prepared-image
creation and refresh, with each consuming run retaining their provenance.

Local harness regression tests require Bash, curl, Python 3, and coreutils on the development
host. They use fake privileged commands, temporary files, and loopback sockets without
launching VMs or touching the host firewall or systemd.

The archive contains image fingerprints, package/kernel details, guest journals, firewall
snapshots, and scenario logs. Frozen installer, guest scripts, and matrix configuration are
under `inputs/`, with hashes in `inputs/SHA256.json`. Candidate artifacts and their checksum
manifest are under `inputs/release/`; all guests use the same captured inputs. The runner
also checks that the original archive remains unchanged. Upgrade baselines include the captured
archive, installer, and checksum manifest; guests consume the same verified bytes. The baseline
binary creates the old installation's configuration, permanent bans, and caches. Candidate upgrade
checks snapshot that state after baseline sync has completed its own normalization, immediately
before candidate installation, and require byte-for-byte preservation. Separate pre-sync snapshots
still verify preservation after a recognized baseline failure. The upgraded candidate must prove
offline cache readability and enforcement before fresh downloads.
Older baselines without temporary bans exercise missing-state upgrade, while a separate candidate
reinstall check proves nonempty temporary-state preservation. The narrowly recognized historical
Debian 12 baseline failure remains explicit in evidence; any isolated old-cache fixture records
that it was generated by the frozen baseline with fake firewall commands. Its private `sudo`
wrapper accepts only the three fake firewall programs and cannot fall through to real sudo.

Before restarting or deleting a guest during diagnostics, the runner also saves agent-independent
evidence under `<target>/host-diagnostics/`: the serial console where supported, available runtime-log
listing, and advertised QEMU logs. Each capture is capped at 1 MiB; adjacent `*.capture.json` records
identify truncation and command errors. Incus versions that explicitly reject VM console-log retrieval
produce an `unsupported` record and a report warning, with the original response and status retained.
This does not count as captured serial evidence. QEMU runtime logs remain required; unexpected console
errors and failed runtime-log captures remain diagnostic failures. Failed captures retain their available
output, other captures still run, and diagnostics never exempt the VM from cleanup.

Every fresh preparation saves `<target>/pre-reboot/snapshot.log` and its adjacent
`snapshot.capture.json` on the host before the controlled reboot. The snapshot records current and
intended kernels, boot ID, final boot configuration and BLS entries, GRUB environment, SELinux/relabel
state, and available agent service configuration, executable labels, and recent journal messages.
Capture has a 30-second deadline and 1 MiB limit; truncation is explicit in the metadata. Capture
failure prevents reboot and retains partial output. Later diagnostics and cleanup preserve this
snapshot even if the guest agent never returns. Warm prepared-image clones retain their existing
admission checks without repeating the fresh-preparation snapshot.

Preparation records boot transitions and agent context before enforcement; the detached enforcement
job saves its own log and exit status. Fedora preparation measures filesystem-relative kernel and
initramfs paths: `/boot/vmlinuz-…` for the observed shared root/boot layout and `/vmlinuz-…` for a
separate boot filesystem. It verifies that both artifacts belong to the measured GRUB filesystem,
repairs stale image-builder root arguments, and establishes the EFI forwarding stub and canonical
GRUB selection. Validation recognizes the generated header and guarded fallback-counting block,
rejects unexpected overrides, and clears next-entry and boot-counter overrides for the qualification
boot. It rechecks the final boot configuration after SELinux argument changes. Post-reboot admission
still requires the exact intended kernel, required modules, and enforcing SELinux.

The retained Fedora failures include a confirmed post-reboot kernel mismatch and later preparation
parser failures. The earlier guest-agent timeout lacks sufficient evidence to establish its cause.
The new snapshot improves diagnosis of a recurrence; it does not establish a fix for that historical
timeout. Captured Fedora configurations now back the isolated regressions, while real VM acceptance
remains a separate user-run check.

Inspect archive contents without unpacking everything:

```bash
tar -tzf "$run_dir/evidence.tar.gz"
tar -xOf "$run_dir/evidence.tar.gz" ./inputs/SHA256.json
tar -xOf "$run_dir/evidence.tar.gz" ./debian-13/preparation.json
tar -xOf "$run_dir/evidence.tar.gz" ./fedora-44/pre-reboot/snapshot.log
```

Working evidence lives in `.evidence/` during execution and is removed only after archive
creation succeeds. Archive failures or abrupt termination can leave that directory behind;
retain it for diagnosis. Success, failure, and handled interruption all attempt archive
finalization. Existing historical results keep their original layout and need no migration.

Required target provisioning failures and application assertion failures produce a failing exit status.
Advisory target prerequisite and application failures remain visible in the summary and structured
results. Cleanup, shared infrastructure, and evidence archive failures still fail the run. Inspect the
earliest failed command and its diagnostics before retrying.

The report distinguishes overall wall time, active stage time, parked time, preparation builds,
cache hits, and reused historical durations. Overall wall time covers runner execution and evidence
archive finalization; the external candidate build and packaging are excluded. Do not sum overlapping
target durations to infer wall time. Required-gate success and all-selected-target success are separate
outcomes; inspect advisory failures, actual firewall backends, and security states before claiming
seven-platform qualification.
Diagnostic failures remain failures or incomplete evidence rather than a target PASS.

VMs are deleted after diagnostics by default. `--keep-failed` marks failed guests for retention
and stops them for inspection, so they do not consume another worker's running-VM slot or get
removed by startup recovery. SIGINT, SIGTERM, and SIGHUP request cancellation and cleanup;
cleanup continues across other guests if one deletion fails. A forced kill or host shutdown
cannot execute cleanup, so the next run recovers abandoned guests under the ownership checks above.
Legacy guests without the retention marker are treated as abandoned after their owner process exits.
Logs and evidence remain on disk. Ownership records also support explicit cleanup:

```bash
just e2e-clean RUN_ID
```

If the run used `KIDOBO_E2E_RESULTS_DIR`, pass the same results root during cleanup so the
runner can find its ownership manifest. Cleanup only removes VMs whose suite ownership and
run identity match recorded resources. Do not remove the shared project, bridge, or storage pool to clean a single run.

## Validate a harness change

Agents must not launch the VM matrix unless explicitly and expressly asked. Local harness
regressions use fake commands, temporary roots, and loopback fixtures. `just ci` does not establish
VM acceptance. The earlier historical runs below also do not qualify a changed validation contract.

Use the same captured archive and tag for cold/warm comparison. The following cold command
rebuilds preparation images and runs every configured target in the detached session:

```bash
release_archive="${RELEASE_ARCHIVE:?set RELEASE_ARCHIVE to the captured candidate archive}"
release_tag="${RELEASE_TAG:?set RELEASE_TAG to the candidate tag}"
just e2e --archive "$release_archive" --tag "$release_tag" --refresh-images
```

Attach with `tmux attach -t kidobo-e2e` while the run is active, then review its saved output
and exit status. After the cold run has completed, launch the warm run against the identical archive:

```bash
just e2e --archive "$release_archive" --tag "$release_tag"
```

The warm command reuses eligible prepared images and reruns every selected application lifecycle.
It creates a new report rather than crediting completed application coverage from resume.
Both sessions close automatically when their commands finish.

User-run acceptance should also cover compatible resume. Verify enforcing SELinux on all three advisory targets and
both nftables and legacy backend coverage. Full seven-platform qualification requires all selected
targets to pass, even though publication requires only four. Compare cold/warm wall time and stage
timings; report measured savings and identify any unverified paths.

The separate Debian 11/Alpine gate verifies static-binary startup and offline lookup only. It is not
full firewall or systemd qualification on those platforms.

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

The fresh seven-target candidate run `run-1792709674-661101` is still in progress. Its
completion and corrected-release published smoke remain separate acceptance milestones.
