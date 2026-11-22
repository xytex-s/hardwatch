# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Project skeleton: `src` layout, `pyproject.toml`, Apache-2.0 licence.
- `hardwatch --version` and `python -m hardwatch` entry points.
- Tooling: pytest with coverage, mypy in strict mode, ruff lint (including security rules)
  and formatting.
- CI on GitHub Actions: lint job, then tests on Ubuntu and Windows for Python 3.11–3.13,
  with read-only workflow permissions.
- Dependabot updates for development tools and GitHub Actions.
- README, SECURITY policy and this changelog.
