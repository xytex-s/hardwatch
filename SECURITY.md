# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub:
**Security → Report a vulnerability** on this repository. Do not open a public issue.

Include the hardwatch version, your distribution and release, and steps to reproduce.
I aim to acknowledge reports within 7 days. This is a personal project maintained in
spare time, so fixes may take longer.

## Supported versions

Only the latest release receives fixes while the project is below 1.0.

## How hardwatch protects itself

A security tool is often run as root and reads data an attacker can influence, so it is
a target in its own right. These rules apply to all code in this repository:

| Risk | Control |
| --- | --- |
| Terminal or report injection via log lines | All untrusted text is sanitised (control characters and ANSI escapes removed) before output |
| Command injection | No `shell=True`; only a fixed allowlist of commands, passed as argument lists, with timeouts |
| Path tricks under `--root` | Paths are resolved and must stay inside the audit root |
| Malicious rule files | Rules are TOML data; nothing in a rule file is executed |
| Excess privilege | Read-only by design; works without root; never self-elevates |
| Secrets in reports | Reports record setting names and values, never whole files or password hashes |
| Supply chain | No runtime dependencies; development tools pinned and updated through Dependabot |

Some of these controls arrive with the features they protect; each is covered by tests
when it lands.
