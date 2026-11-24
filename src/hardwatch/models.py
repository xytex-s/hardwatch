"""Core data types shared by checks, rules and reporters.

Everything here is immutable. Once a check returns a Finding, nothing later in
the pipeline (a reporter, a filter, a bug) can quietly change its result.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType

CHECK_ID_PATTERN = re.compile(r"HW-[A-Z]{2,5}-\d{3}")


class Severity(StrEnum):
    """How much a failed check matters. Compare with ``at_least``, not ``<``."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    def at_least(self, other: Severity) -> bool:
        return self.rank >= other.rank


# StrEnum members compare as strings ("high" < "low" alphabetically), so the
# real ordering lives here and is used through Severity.rank.
_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Status(StrEnum):
    """The outcome of one check on one host."""

    PASS = "pass"  # noqa: S105  (a status name, not a password)
    FAIL = "fail"
    WARN = "warn"  # could not decide cleanly; a human should look
    SKIP = "skip"  # not run, e.g. needs root or the service is not installed
    ERROR = "error"  # the check itself broke


@dataclass(frozen=True, slots=True)
class CheckMeta:
    """What a check is, independent of any host it runs on."""

    id: str
    title: str
    category: str
    severity: Severity
    requires_root: bool = False
    references: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not CHECK_ID_PATTERN.fullmatch(self.id):
            raise ValueError(f"invalid check id {self.id!r}: expected a form like HW-SSH-001")
        if not self.title.strip():
            raise ValueError(f"{self.id}: title must not be empty")
        if not self.category.strip():
            raise ValueError(f"{self.id}: category must not be empty")


@dataclass(frozen=True, slots=True)
class Finding:
    """The result of running one check.

    ``message`` says what was found. ``evidence`` records the setting and value
    that led to the result (never whole files or secrets). A FAIL must carry a
    ``remediation`` so every problem reported comes with a way to fix it.
    """

    check: CheckMeta
    status: Status
    message: str
    evidence: Mapping[str, str] = field(default_factory=dict)
    remediation: str | None = None

    def __post_init__(self) -> None:
        if not self.message.strip():
            raise ValueError(f"{self.check.id}: finding message must not be empty")
        if self.status is Status.FAIL and not (self.remediation and self.remediation.strip()):
            raise ValueError(f"{self.check.id}: a failing finding must say how to fix it")
        # Copy, then wrap read-only: the caller's dict can change later without
        # affecting this finding, and nobody can mutate it through the finding.
        object.__setattr__(self, "evidence", MappingProxyType(dict(self.evidence)))

    @property
    def severity(self) -> Severity:
        return self.check.severity

    @property
    def failed(self) -> bool:
        return self.status is Status.FAIL
