# Security Policy

Thank you for helping keep Kidobo and its users secure. This policy explains
which versions receive security fixes, how to report a suspected vulnerability,
and what to expect after reporting it.

## Supported Versions

Only the latest published release receives security fixes. Please confirm that
an issue affects the latest release before reporting it when practical. Reports
against the current development branch are also welcome, but the development
branch is not a supported release.

| Version | Supported |
| --- | --- |
| Latest published release | Yes |
| Older releases | No |

## Reporting a Vulnerability

[Report suspected vulnerabilities privately through GitHub][report]. If you
are unsure whether an issue has security impact, use the private reporting
channel and let the maintainers assess it.

Do not disclose vulnerability details in a public GitHub issue, discussion,
pull request, social media post, or other public channel. Report ordinary bugs
without security impact through [GitHub Issues][issues].

Include as much of the following information as is available:

- The affected Kidobo release, tag, or commit.
- The installation method, operating system, and relevant environment details.
- A description of the impact and the security boundary that can be crossed.
- Reproduction steps or a minimal proof of concept.
- Sanitized logs, configuration, or command output that supports the report.
- Any known workarounds or mitigations.
- Whether the issue or its details have already been shared elsewhere.
- Your intended public disclosure date, if you have one.

Remove unrelated credentials, personal data, and secrets from all submitted
material. If sensitive data is necessary to demonstrate the issue, include only
the minimum needed in the private report.

## Scope

This policy covers vulnerabilities in:

- Kidobo source code and documented workflows.
- Official Kidobo release binaries, archives, and checksums.
- The Kidobo installer and uninstall path.
- Generated systemd units and Kidobo-managed firewall or ipset behavior.
- Kidobo's use of an upstream dependency, operating-system facility, or remote
  service when that integration creates the vulnerability.

The following are outside the scope of this policy unless Kidobo's integration
is the cause of the security impact:

- Vulnerabilities in GitHub or other third-party services.
- Vulnerabilities in remote-feed operators or the content and availability of
  third-party blocklists.
- Vulnerabilities in the operating system, `iptables`, `ip6tables`, `ipset`,
  systemd, or other upstream tools.
- Issues that affect only unsupported older Kidobo releases.
- Configuration questions, support requests, and ordinary functional defects
  without security impact.

Report vulnerabilities in third-party components directly to their respective
maintainers.

## Research Guidelines

To remain within this policy:

- Test only systems you own or systems for which you have explicit permission
  to conduct security research.
- Prefer isolated, disposable environments and fake external commands. Do not
  perform destructive firewall testing on production systems.
- Do not probe GitHub, remote-feed operators, or other third-party services as
  part of testing Kidobo.
- Do not use social engineering, denial of service, service degradation,
  persistence, destructive actions, or high-volume automated testing.
- Minimize access to data. Do not alter, retain, exfiltrate, or disclose data
  that does not belong to you.
- Stop testing and submit a private report if you encounter sensitive data or
  gain unintended access to a system or account.
- Comply with applicable laws and keep vulnerability details confidential
  until the coordinated disclosure date.

## Safe Harbor

When you make a good-faith effort to follow this policy, the Kidobo maintainers
consider your research within the scope of this policy to be authorized. We
will not initiate or support legal action against you for accidental,
good-faith violations of this policy. If you discover that your activity may
not comply with this policy, stop and report the concern privately so that we
can work with you to resolve it.

This safe harbor applies only to claims under the control of the Kidobo
maintainers. It does not authorize research against third-party systems, bind
independent third parties, or waive your responsibility to comply with
applicable law. If you are uncertain whether planned research is covered, ask
through the private reporting channel before proceeding.

This section is adapted from the [disclose.io Simple Safe Harbor][safe-harbor].

## What to Expect

The maintainers aim to:

- Acknowledge a report within 7 calendar days.
- Provide an initial assessment within 14 calendar days of the report.
- Provide a progress update at least every 14 calendar days while the report
  remains unresolved.

The initial assessment will normally state whether the report is accepted,
rejected, considered a duplicate, or requires more information. When practical,
it will also describe the expected next steps. These response times are goals,
not guarantees, and remediation time depends on impact and complexity.

## Coordinated Disclosure

The target for public disclosure is within 90 calendar days of the initial
private report, normally alongside a fixed release or a practical mitigation.
Disclosure may happen sooner when there is active exploitation, urgent risk to
users, or mutual agreement to an earlier date. A later disclosure date requires
mutual agreement with the reporter.

If a fix is not ready by the coordinated date, the maintainers and reporter
should coordinate an advisory that explains the known impact, available
mitigations, and fix status. Please keep the report and its details confidential
until the coordinated disclosure date.

## No Bug Bounty

Kidobo does not operate a bug-bounty program. Submitting a report does not
create an entitlement to compensation, and no payment is promised.

[issues]: https://github.com/blwarren/kidobo/issues
[report]: https://github.com/blwarren/kidobo/security/advisories/new
[safe-harbor]: https://disclose.io/framework/terms/simple-safe-harbor/
