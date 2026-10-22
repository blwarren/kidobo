# Distro lifecycle testing

The Incus suite installs and operates Kidobo in disposable QEMU/KVM virtual machines,
including real guest firewall and systemd operations. It supplements `just ci` and the
Debian/Alpine static compatibility checks. Publication requires the full candidate matrix
before any release push or upload; published-release smoke testing is separate. `just ci`
keeps its existing local checks and does not launch VMs.

## Host preparation

Use an x86-64 Linux host with hardware virtualization enabled, usable `/dev/kvm`, and an
installed, running Incus server with VM support. Follow the official
[Incus installation guide](https://linuxcontainers.org/incus/docs/main/installing/) for your
host distribution and arrange access to its local daemon. The setup command does not install
host packages, change user groups, or initialize unrelated Incus resources. Release builds
also need the repository's pinned Rust target, `musl-gcc`, `readelf`, and `just`.

Install `genisoimage` or `mkisofs` on the host to generate the agent configuration ISO.
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
The Leap packaged `bgpq4` prerequisite must pass; the suite does not build replacements.

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
instance-name prefix printed when each fresh VM starts. Results include `summary.txt`,
`results.json`, numbered command logs, and per-distro guest diagnostics and state. They record
image fingerprints, artifact hashes, package and kernel details, guest journals, and firewall
evidence. The run freezes its installer, guest scripts, and matrix configuration under
`inputs/`, with their SHA-256 hashes in `inputs/SHA256.json`; guests use these captured
scripts throughout the run. Candidate archives and their checksum manifest are copied into
`inputs/release/` before any VM starts, so every distro receives the same private artifact
snapshot. The runner checks that the original archive remains unchanged during testing.
Guest state and its scenario logs are copied back before cleanup.

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

The complete latest matrix has not passed. These provisional results establish the observed
coverage while host ISO tooling and a rerun with the latest assertions remain pending:

`just ci` and `just coverage` passed locally. Coverage was 92.53% of regions, 93.65% of
functions, and 93.02% of lines with the existing thresholds. These checks do not establish
VM matrix acceptance.

| Lane | Target | Observed result | Elapsed |
| --- | --- | --- | --- |
| Candidate | Debian 13 | Full lifecycle passed in `run-1792701146-490083` | 236.6 s |
| Published | Debian 13 | Smoke passed | 99.2 s |
| Published | Ubuntu 24.04 | Smoke passed | 77.1 s |
| Published | Ubuntu 26.04 | Smoke passed | 100.6 s |
| Published | Fedora 44 | Smoke passed | 116.5 s |
| Published | Debian 12 | Application failed while probing an absent firewall chain | — |
| Published | AlmaLinux 9 and 10 | Guest agent unavailable; agent configuration disk support required | — |
| Published | openSUSE Leap 16.0 | Provisioning failed: packaged `bgpq4` unavailable | — |

Published observations came from the eight-target run `run-1792701111-488918`. Debian 12's
iptables diagnostic for an absent chain exposed an application compatibility issue; the suite
does not substitute a successful result. AlmaLinux diagnosis led to attaching an agent
configuration ISO to every VM, which requires the newly documented host ISO utility. Its
installation and subsequent matrix validation are still pending. Later assertions also need
a complete rerun before publication can pass.

The earlier complete candidate attempt `run-1792700407-470030` exposed harness assertion
issues that were subsequently corrected; it is not a successful matrix result. The focused
Debian 13 candidate result above likewise does not establish eight-target acceptance.

Elapsed values come from the runner's per-target measurements and include provisioning,
application checks, diagnostics, and cleanup. The host image cache was already populated;
these are not cold image download benchmarks. Retained run evidence records image
fingerprints, package updates, and kernel/backend versions for comparisons. No VM success
claim follows from compilation or fixture tests alone.
