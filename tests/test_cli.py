from __future__ import annotations

import subprocess
import sys

import pytest

from hardwatch import __version__
from hardwatch.cli import EXIT_USAGE, main


def test_version_flag_prints_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert capsys.readouterr().out.strip() == f"hardwatch {__version__}"


def test_no_command_prints_help_and_returns_usage_code(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main([]) == EXIT_USAGE
    out = capsys.readouterr().out
    assert "usage: hardwatch" in out
    assert "never changes the system" in out


def test_unknown_option_is_a_usage_error() -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--definitely-not-a-flag"])
    assert exc.value.code == EXIT_USAGE


def test_runs_as_module() -> None:
    # Fixed argv list, no shell: the same rule the tool itself follows.
    result = subprocess.run(
        [sys.executable, "-m", "hardwatch", "--version"],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert result.returncode == 0
    assert __version__ in result.stdout
