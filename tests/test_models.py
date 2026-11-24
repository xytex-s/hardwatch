from __future__ import annotations

import dataclasses

import pytest

from hardwatch.models import CheckMeta, Finding, Severity, Status

SSH_ROOT_LOGIN = CheckMeta(
    id="HW-SSH-001",
    title="Root login over SSH is disabled",
    category="ssh",
    severity=Severity.HIGH,
)


def test_severity_orders_by_rank_not_alphabet() -> None:
    # As plain strings "high" < "low"; the rank must win.
    assert Severity.HIGH.at_least(Severity.LOW)
    assert not Severity.LOW.at_least(Severity.HIGH)
    assert Severity.MEDIUM.at_least(Severity.MEDIUM)
    assert [s.rank for s in Severity] == [0, 1, 2, 3, 4]


@pytest.mark.parametrize("bad_id", ["", "SSH-001", "HW-ssh-001", "HW-SSH-1", "HW-SSH-0001", "x"])
def test_check_meta_rejects_malformed_ids(bad_id: str) -> None:
    with pytest.raises(ValueError, match="invalid check id"):
        CheckMeta(id=bad_id, title="t", category="c", severity=Severity.LOW)


def test_check_meta_rejects_blank_title() -> None:
    with pytest.raises(ValueError, match="title"):
        CheckMeta(id="HW-SSH-002", title="  ", category="ssh", severity=Severity.LOW)


def test_failing_finding_must_include_a_fix() -> None:
    with pytest.raises(ValueError, match="how to fix"):
        Finding(SSH_ROOT_LOGIN, Status.FAIL, "PermitRootLogin is yes")
    with pytest.raises(ValueError, match="how to fix"):
        Finding(SSH_ROOT_LOGIN, Status.FAIL, "PermitRootLogin is yes", remediation="   ")


def test_passing_finding_needs_no_fix() -> None:
    finding = Finding(SSH_ROOT_LOGIN, Status.PASS, "PermitRootLogin is no")
    assert not finding.failed
    assert finding.severity is Severity.HIGH


def test_finding_is_immutable() -> None:
    finding = Finding(SSH_ROOT_LOGIN, Status.PASS, "ok")
    with pytest.raises(dataclasses.FrozenInstanceError):
        finding.status = Status.FAIL  # type: ignore[misc]


def test_evidence_is_copied_and_read_only() -> None:
    evidence = {"PermitRootLogin": "yes"}
    finding = Finding(
        SSH_ROOT_LOGIN,
        Status.FAIL,
        "Root login is allowed",
        evidence=evidence,
        remediation="Set PermitRootLogin no",
    )
    evidence["PermitRootLogin"] = "no"  # changing the original afterwards...
    assert finding.evidence["PermitRootLogin"] == "yes"  # ...does not change the finding
    with pytest.raises(TypeError):
        finding.evidence["PermitRootLogin"] = "no"  # type: ignore[index]
