"""Privilege detection.

hardwatch never elevates itself. It only asks "am I root?" so it can skip
root-only checks honestly and tell the user what it skipped.
"""

from __future__ import annotations

import os

ROOT_NOTICE = (
    "Running as root. hardwatch is read-only: it reads configuration files and runs "
    "a fixed list of read-only commands, and changes nothing."
)


def is_root() -> bool:
    """True if the effective user is root. Always False where there is no euid (Windows)."""
    geteuid = getattr(os, "geteuid", None)
    if geteuid is None:
        return False
    return bool(geteuid() == 0)
