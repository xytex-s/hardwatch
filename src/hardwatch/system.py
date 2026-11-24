"""The only module that touches the operating system.

It does two things:

* reads files under an audit root (normally ``/``) and refuses any path that
  would leave it;
* runs commands from a fixed allowlist, by name, with no arguments taken from
  anywhere else.

Collectors and checks receive a ``SystemView`` and never call ``open()``,
``os`` or ``subprocess`` themselves. Tests give them a fixture directory and a
fake runner, which is why the suite runs on Windows as well as Linux.
"""

from __future__ import annotations

import os
import stat
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Protocol

MAX_READ_BYTES = 1024 * 1024  # 1 MiB; no file we audit is anywhere near this size
COMMAND_TIMEOUT_SECONDS = 10.0

# Logical name -> exact argv. Absolute paths, so a planted binary earlier in
# PATH is never picked up. Nothing read from a config file, a log or the user
# ever becomes part of a command line, so there is nothing to inject into.
ALLOWED_COMMANDS: Mapping[str, tuple[str, ...]] = MappingProxyType(
    {
        "sshd-effective-config": ("/usr/sbin/sshd", "-T"),
        "listening-sockets": ("/usr/bin/ss", "-H", "-tulpn"),
    }
)

# Minimal, fixed environment for child processes. LC_ALL=C gives stable,
# English, parseable output whatever the host's locale is.
_SAFE_ENV: Mapping[str, str] = MappingProxyType(
    {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
)


class SystemAccessError(Exception):
    """Base class for every refusal or failure in this module."""


class PathOutsideRootError(SystemAccessError):
    """The path is malformed or resolves outside the audit root."""


class NotRegularFileError(SystemAccessError):
    """The path exists but is not a regular file (directory, FIFO, device...)."""


class FileTooLargeError(SystemAccessError):
    """The file is bigger than the read limit."""


class CommandNotAllowedError(SystemAccessError):
    """The command name is not in the allowlist."""


class CommandUnavailableError(SystemAccessError):
    """The command is allowed but cannot run here (not installed, disabled, no response)."""


class CommandTimeoutError(SystemAccessError):
    """The command did not finish in time."""


@dataclass(frozen=True, slots=True)
class CommandResult:
    name: str
    returncode: int
    stdout: str
    stderr: str = ""

    @property
    def ok(self) -> bool:
        return self.returncode == 0


class Runner(Protocol):
    def run(self, name: str) -> CommandResult: ...


def resolve_command(name: str, commands: Mapping[str, tuple[str, ...]]) -> tuple[str, ...]:
    """Look a command name up in an allowlist, or refuse."""
    try:
        return commands[name]
    except KeyError:
        raise CommandNotAllowedError(f"command {name!r} is not in the allowlist") from None


class SubprocessRunner:
    """Runs allowlisted commands for real. Only meaningful on the Linux host being audited."""

    def __init__(
        self,
        commands: Mapping[str, tuple[str, ...]] = ALLOWED_COMMANDS,
        timeout: float = COMMAND_TIMEOUT_SECONDS,
    ) -> None:
        self._commands = commands
        self._timeout = timeout

    def run(self, name: str) -> CommandResult:
        argv = resolve_command(name, self._commands)
        if not os.path.isfile(argv[0]):
            raise CommandUnavailableError(f"{argv[0]} is not installed")
        try:
            # No shell, fixed argv from the allowlist, no stdin, minimal env, timeout.
            proc = subprocess.run(  # noqa: S603
                argv,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                env=dict(_SAFE_ENV),
                timeout=self._timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise CommandTimeoutError(f"{name} did not finish within {self._timeout}s") from exc
        except OSError as exc:
            raise CommandUnavailableError(f"{name} could not be started: {exc}") from exc
        return CommandResult(name, proc.returncode, proc.stdout, proc.stderr)


class SystemView:
    """Read-only access to one host, rooted at ``root``.

    Every path is written as it would be on the audited host (``/etc/ssh/sshd_config``)
    and mapped under ``root``. Paths that are malformed, or that resolve outside
    ``root`` through ``..`` or a symlink, are refused.

    Known limits:

    * Absolute symlinks inside an offline root (``--root /mnt/vm``) point at the
      auditing machine, so they are refused, not followed into the image.
    * There is a small window between checking a path and opening it. Exploiting
      it needs write access to the audited files, at which point the host is
      already compromised; the check still stops accidental and casual escapes.
    """

    def __init__(
        self,
        root: str | os.PathLike[str] = "/",
        runner: Runner | None = None,
        *,
        allow_commands: bool = True,
        max_read_bytes: int = MAX_READ_BYTES,
    ) -> None:
        resolved = Path(root).resolve(strict=True)
        if not resolved.is_dir():
            raise NotADirectoryError(f"audit root is not a directory: {resolved}")
        self._root = resolved
        self._runner: Runner = runner if runner is not None else SubprocessRunner()
        self._allow_commands = allow_commands
        self._max_read_bytes = max_read_bytes

    @property
    def root(self) -> Path:
        return self._root

    # ------------------------------------------------------------------ paths

    def resolve(self, path: str) -> Path:
        """Map a host path to a real path under the root, or raise PathOutsideRootError."""
        if "\x00" in path:
            raise PathOutsideRootError("path contains a NUL byte")
        if "\\" in path:
            # On Windows a backslash is a separator, so it could smuggle in "..".
            raise PathOutsideRootError(f"backslashes are not allowed in audit paths: {path!r}")
        host_path = PurePosixPath(path)
        if not host_path.is_absolute():
            raise PathOutsideRootError(f"audit paths must be absolute: {path!r}")

        candidate = self._root.joinpath(*host_path.parts[1:])
        resolved = candidate.resolve(strict=False)  # follows symlinks and ".."
        if not resolved.is_relative_to(self._root):
            raise PathOutsideRootError(f"{path!r} resolves outside the audit root")
        return resolved

    def exists(self, path: str) -> bool:
        return self.resolve(path).exists()

    def stat(self, path: str) -> os.stat_result:
        """Stat a file (after following symlinks inside the root)."""
        return self.resolve(path).stat()

    def read_text(self, path: str) -> str:
        """Read a regular file as UTF-8 (bad bytes replaced), up to the size limit.

        Raises FileNotFoundError or PermissionError as the OS reports them, so
        callers can tell "missing" from "needs root".
        """
        target = self.resolve(path)
        mode = target.stat().st_mode
        if not stat.S_ISREG(mode):
            # A FIFO named like a config file would otherwise hang the audit forever.
            raise NotRegularFileError(f"{path!r} is not a regular file")
        with target.open("rb") as handle:
            data = handle.read(self._max_read_bytes + 1)
        if len(data) > self._max_read_bytes:
            raise FileTooLargeError(f"{path!r} is larger than {self._max_read_bytes} bytes")
        return data.decode("utf-8", errors="replace")

    def list_dir(self, path: str) -> list[str]:
        """Names in a directory, sorted, so results are the same on every run."""
        return sorted(entry.name for entry in self.resolve(path).iterdir())

    # --------------------------------------------------------------- commands

    def run(self, name: str) -> CommandResult:
        if not self._allow_commands:
            raise CommandUnavailableError(
                "commands are disabled for this audit: their output would describe "
                "the machine running hardwatch, not the audit root"
            )
        return self._runner.run(name)
