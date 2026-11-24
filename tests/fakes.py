"""Test doubles. Kept out of the shipped package on purpose."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

from hardwatch.system import (
    ALLOWED_COMMANDS,
    CommandResult,
    CommandUnavailableError,
    SystemAccessError,
    resolve_command,
)


@dataclass
class FakeRunner:
    """Returns canned command output instead of running anything.

    It applies the same allowlist as the real runner, so a typo in a command
    name fails in tests exactly as it would on a real host.
    """

    responses: dict[str, CommandResult | SystemAccessError] = field(default_factory=dict)
    commands: Mapping[str, tuple[str, ...]] = field(default_factory=lambda: ALLOWED_COMMANDS)
    calls: list[str] = field(default_factory=list)

    def add(self, name: str, stdout: str = "", returncode: int = 0, stderr: str = "") -> None:
        self.responses[name] = CommandResult(name, returncode, stdout, stderr)

    def fail_with(self, name: str, error: SystemAccessError) -> None:
        self.responses[name] = error

    def run(self, name: str) -> CommandResult:
        resolve_command(name, self.commands)
        self.calls.append(name)
        response = self.responses.get(name)
        if response is None:
            raise CommandUnavailableError(f"no fake response configured for {name!r}")
        if isinstance(response, SystemAccessError):
            raise response
        return response
