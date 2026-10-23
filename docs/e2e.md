# Distro lifecycle testing

The Incus suite installs and operates Kidobo in disposable QEMU/KVM virtual machines,
including real guest firewall and systemd operations. It supplements `just ci` and the
Debian/Alpine static compatibility checks. Publication requires the full candidate matrix
before any release push or upload; published-release smoke testing is separate. `just ci`
keeps its existing local checks and does not launch VMs.

The mandatory matrix has seven targets: Debian 12 and 13, Ubuntu 24.04 and 26.04, Fedora 44,
and AlmaLinux 9 and 10. Every configured target must pass before publication.

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
to generate the agent configuration ISO.
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
and resource settings. Defaults are sequential execution with 2 vCPUs, 4 GiB memory, and a
30 GiB virtual disk per VM. Reserve additional storage for images and failure artifacts.
Incus images and distro repositories require network access.

Every run launches fresh VMs, updates each selected distro within its pinned release line,
installs packaged prerequisites, and reboots before application testing. AlmaLinux enables
EPEL/CRB. Package failures, unavailable images, or missing kernel support fail the run.
The suite requires packaged prerequisites and does not build replacements for unavailable
packages.

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

```bash
just e2e
just e2e --distro debian-12 --keep-failed
just e2e-published
just e2e-published "${RELEASE_TAG:?set RELEASE_TAG to a published tag}" --distro debian-12
```

Candidate testing builds the static release binary and uses the same archive packager as
publication. `just e2e` writes each archive into a new directory under
`target/e2e-candidate/<tag>/`; concurrent invocations do not overwrite each other. Each
guest serves the captured archive through a local HTTP fixture and runs the real
installer, including checksums, extraction, and binary replacement. The installer variable
`KIDOBO_RELEASE_BASE_URL` selects this release directory and requires an explicit `--version`;
normal installation continues to download from GitHub.

The candidate lane covers initialization, preserved configuration, offline inspection,
IPv4/IPv6 blocked and allowed traffic, safelists, source edits, systemd/timer execution,
reboot recovery, failure preservation, upgrade, flush, and uninstall. Probes use network
namespaces inside guests; host firewall commands are never test targets. Each distro keeps
its installed iptables backend and security configuration. HTTP fixtures make source data
deterministic; external IRR query availability is outside the gate.

The published lane resolves `latest` once and installs the selected release from genuine
GitHub assets, then tests initialization, configuration, doctor, synchronization, and
uninstall. Provisioning still updates and reboots each fresh guest before installing Kidobo.
This smoke lane omits the candidate's post-install reboot and upgrade scenarios. It requires
GitHub access and runs independently of publication.

Published `v0.14.3` assets are immutable and still reproduce the Debian 12 missing-chain
failure recorded below. They cannot validate the subsequent candidate fix. After publishing
a corrected release through the candidate gate, run `just e2e-published <corrected-tag>`
as a separate post-publication smoke milestone across all seven mandatory targets.

For an existing release archive, including publisher use:

```bash
release_tag="${RELEASE_TAG:?set RELEASE_TAG to the packaged candidate tag}"
release_archive="${RELEASE_ARCHIVE:?set RELEASE_ARCHIVE to the existing tar.gz path}"
just e2e-artifact "${release_archive}" "${release_tag}"
```

This command runs all configured targets. A filtered diagnosis is not a passing publication
gate. Changing the matrix changes release coverage and should be reviewed accordingly.

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
stderr reflects when the runner observed the output. Shell tracing includes script, function,
and line context and uses a separate descriptor so captured command results remain intact.

The archive contains image fingerprints, package/kernel details, guest journals, firewall
snapshots, and scenario logs. Frozen installer, guest scripts, and matrix configuration are
under `inputs/`, with hashes in `inputs/SHA256.json`. Candidate artifacts and their checksum
manifest are under `inputs/release/`; all guests use the same captured inputs. The runner
also checks that the original archive remains unchanged. Inspect archive contents without
unpacking everything:

```bash
tar -tzf "$run_dir/evidence.tar.gz"
tar -xOf "$run_dir/evidence.tar.gz" ./inputs/SHA256.json
tar -xOf "$run_dir/evidence.tar.gz" ./debian-13/state/provision.txt
```

Working evidence lives in `.evidence/` during execution and is removed only after archive
creation succeeds. Archive failures or abrupt termination can leave that directory behind;
retain it for diagnosis. Success, failure, and handled interruption all attempt archive
finalization. Existing historical results keep their original layout and need no migration.

Provisioning failures and application assertion failures both produce a failing exit status. Inspect the earliest failed command and its diagnostics before retrying.

VMs are deleted after diagnostics by default. `--keep-failed` retains failed guests for
inspection. Interrupted runs retain ownership records so cleanup can be retried safely:

```bash
just e2e-clean RUN_ID
```

If the run used `KIDOBO_E2E_RESULTS_DIR`, pass the same results root during cleanup so the
runner can find its ownership manifest. Cleanup only removes VMs whose suite ownership and
run identity match recorded resources. Do not remove the shared project, bridge, or storage pool to clean a single run.

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
