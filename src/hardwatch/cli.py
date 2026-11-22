"""Command-line entry point.

Exit codes (documented in the README and kept stable):
    0  ran successfully, nothing at or above --fail-on
    1  ran successfully, findings at or above --fail-on
    2  usage error
    3  internal error
"""

from __future__ import annotations

import argparse
from collections.abc import Sequence

from hardwatch import __version__

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2
EXIT_INTERNAL = 3


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hardwatch",
        description=(
            "Read-only hardening and detection-readiness auditor for Debian and Ubuntu. "
            "It never changes the system it runs on."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    # Subcommands (audit, detect, list, explain, rules) are added in later milestones.
    parser.add_subparsers(dest="command", metavar="COMMAND")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return an exit code. ``argv`` defaults to ``sys.argv[1:]``."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return EXIT_USAGE

    # Not reachable until subcommands exist. parser.error() exits with EXIT_USAGE.
    parser.error(f"unknown command: {args.command}")  # pragma: no cover
