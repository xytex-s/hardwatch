# hardwatch

[![CI](https://github.com/xytex-s/hardwatch/actions/workflows/ci.yml/badge.svg)](https://github.com/xytex-s/hardwatch/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![License](https://img.shields.io/badge/license-Apache--2.0-green)

**Is this server hardened, and would you notice if someone got in anyway?**

hardwatch is a read-only auditor for Debian and Ubuntu servers. It checks security
configuration (SSH, firewall, listening services, updates, accounts, file permissions,
kernel settings), checks whether the logging needed to investigate an attack is in place,
and runs tested detection rules over local logs.

> **Status: pre-alpha.** The project skeleton and CI are in place; no checks exist yet.
> See the [roadmap](#roadmap) for what is coming and in what order.

## Design principles

- **Read-only.** hardwatch never changes the system it runs on. It reports problems and
  suggests fixes as text; you decide whether to apply them.
- **Least privilege.** It runs as a normal user. Checks that need root are reported as
  skipped, never silently passed. It never elevates itself or calls `sudo`.
- **Local only.** It audits the machine it runs on. It does not scan or probe other hosts.
- **No runtime dependencies.** Standard library only, so there is nothing extra to trust
  or patch.
- **Safe with hostile input.** Log lines and config files can contain attacker-controlled
  text. Output is sanitised before it reaches your terminal or a report.

## Scope and responsible use

hardwatch is intended for systems you own or administer. Running it on a machine you
are not authorised to inspect may break your organisation's policy or the law, even
though the tool is read-only. It is a point-in-time audit, not a monitoring system, and
a compromised host can hide things from any tool running on it.

## Roadmap

| Version | Adds |
| --- | --- |
| 0.1.0 | SSH and network checks, text and JSON output |
| 0.2.0 | Updates, accounts, file permission and kernel checks; Markdown reports |
| 0.3.0 | Detection-readiness checks (auditd, journald, log retention, time sync) |
| 0.4.0 | Log rule engine with ATT&CK-mapped, tested detection rules |

## Development

Requires Python 3.11 or newer. CI runs the tests on Linux and Windows: they use fixture
files, not the live system, so you can develop on either.

```bash
git clone https://github.com/xytex-s/hardwatch.git
cd hardwatch
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
python -m pip install -r requirements-dev.txt -e .

pytest                             # tests
ruff check . && ruff format --check .   # lint and formatting
mypy                               # strict type checking
hardwatch --version
```

## Licence

Apache License 2.0. See [LICENSE](LICENSE).
