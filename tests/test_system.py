from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from conftest import MakeRoot
from fakes import FakeRunner
from hardwatch import privileges
from hardwatch.system import (
    CommandNotAllowedError,
    CommandTimeoutError,
    CommandUnavailableError,
    FileTooLargeError,
    NotRegularFileError,
    PathOutsideRootError,
    SubprocessRunner,
    SystemView,
)

SSHD_CONFIG = "PermitRootLogin no\nPasswordAuthentication no\n"


def _symlink_or_skip(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip(
            "this machine does not allow creating symlinks (Windows without Developer Mode)"
        )


# ------------------------------------------------------------------ reading


def test_reads_a_file_inside_the_root(make_root: MakeRoot) -> None:
    view = SystemView(make_root({"/etc/ssh/sshd_config": SSHD_CONFIG}))
    assert view.read_text("/etc/ssh/sshd_config") == SSHD_CONFIG
    assert view.exists("/etc/ssh/sshd_config")
    assert not view.exists("/etc/ssh/missing")


def test_missing_file_raises_file_not_found(make_root: MakeRoot) -> None:
    view = SystemView(make_root({}))
    with pytest.raises(FileNotFoundError):
        view.read_text("/etc/ssh/sshd_config")


def test_invalid_utf8_is_replaced_not_fatal(make_root: MakeRoot) -> None:
    root = make_root({})
    (root / "motd").write_bytes(b"hello \xff\xfe world")
    assert SystemView(root).read_text("/motd") == "hello �� world"


def test_file_over_the_size_limit_is_refused(make_root: MakeRoot) -> None:
    view = SystemView(make_root({"/var/log/big": "x" * 101}), max_read_bytes=100)
    with pytest.raises(FileTooLargeError):
        view.read_text("/var/log/big")


def test_file_exactly_at_the_limit_is_read(make_root: MakeRoot) -> None:
    view = SystemView(make_root({"/var/log/edge": "x" * 100}), max_read_bytes=100)
    assert len(view.read_text("/var/log/edge")) == 100


def test_directory_is_not_read_as_a_file(make_root: MakeRoot) -> None:
    view = SystemView(make_root({"/etc/ssh/sshd_config": SSHD_CONFIG}))
    with pytest.raises(NotRegularFileError):
        view.read_text("/etc/ssh")


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs are POSIX-only")
def test_fifo_is_refused_instead_of_hanging(make_root: MakeRoot) -> None:
    root = make_root({})
    (root / "etc").mkdir()
    os.mkfifo(root / "etc" / "trap")
    with pytest.raises(NotRegularFileError):
        SystemView(root).read_text("/etc/trap")


def test_list_dir_is_sorted(make_root: MakeRoot) -> None:
    root = make_root(
        {"/etc/ssh/sshd_config.d/50-b.conf": "", "/etc/ssh/sshd_config.d/10-a.conf": ""}
    )
    assert SystemView(root).list_dir("/etc/ssh/sshd_config.d") == ["10-a.conf", "50-b.conf"]


# ------------------------------------------------------------ path refusals


@pytest.mark.parametrize(
    ("path", "reason"),
    [
        ("etc/passwd", "must be absolute"),
        ("/etc/pass\x00wd", "NUL byte"),
        ("/etc\\..\\..\\secret", "backslashes"),
    ],
)
def test_malformed_paths_are_refused(make_root: MakeRoot, path: str, reason: str) -> None:
    view = SystemView(make_root({}))
    with pytest.raises(PathOutsideRootError, match=reason):
        view.read_text(path)


def test_symlink_escaping_the_root_is_refused(tmp_path: Path, make_root: MakeRoot) -> None:
    secret = tmp_path / "secret.txt"
    secret.write_text("host secret", encoding="utf-8")
    root = make_root({"/etc/placeholder": ""})
    _symlink_or_skip(root / "etc" / "shadow", secret)

    view = SystemView(root)
    with pytest.raises(PathOutsideRootError, match="outside the audit root"):
        view.read_text("/etc/shadow")


def test_symlink_inside_the_root_is_followed(make_root: MakeRoot) -> None:
    root = make_root({"/usr/share/zoneinfo/UTC": "TZif"})
    _symlink_or_skip(root / "localtime", root / "usr" / "share" / "zoneinfo" / "UTC")
    assert SystemView(root).read_text("/localtime") == "TZif"


def test_root_must_exist(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        SystemView(tmp_path / "nope")


@pytest.mark.parametrize(
    "path",
    [
        "/../secret.txt",
        "/etc/../../secret.txt",
        "/etc/ssh/../../../secret.txt",
    ],
)
def test_parent_traversal_escaping_the_root_is_refused(
    tmp_path: Path,
    make_root: MakeRoot,
    path: str,
) -> None:
    # The secret is outside the audit root, in the temporary area.
    secret = tmp_path / "secret.txt"
    secret.write_text("host secret", encoding="utf-8")

    root = make_root({"/etc/ssh/placeholder": ""})
    view = SystemView(root)

    with pytest.raises(PathOutsideRootError, match="outside the audit root"):
        view.read_text(path)


def test_parent_traversal_inside_the_root_is_allowed(
    make_root: MakeRoot,
) -> None:
    hostname = "test-hostname\n"
    view = SystemView(make_root({"/etc/hostname": hostname}))

    assert view.read_text("/etc/../etc/hostname") == hostname

# ----------------------------------------------------------------- commands


def test_fake_runner_returns_canned_output(make_root: MakeRoot, fake_runner: FakeRunner) -> None:
    fake_runner.add("sshd-effective-config", stdout="permitrootlogin no\n")
    view = SystemView(make_root({}), fake_runner)

    result = view.run("sshd-effective-config")

    assert result.ok
    assert result.stdout == "permitrootlogin no\n"
    assert fake_runner.calls == ["sshd-effective-config"]


def test_fake_runner_enforces_the_real_allowlist(fake_runner: FakeRunner) -> None:
    with pytest.raises(CommandNotAllowedError):
        fake_runner.run("rm-everything")
    assert fake_runner.calls == []


def test_unconfigured_fake_command_is_unavailable(fake_runner: FakeRunner) -> None:
    with pytest.raises(CommandUnavailableError):
        fake_runner.run("listening-sockets")


def test_commands_can_be_disabled(make_root: MakeRoot, fake_runner: FakeRunner) -> None:
    fake_runner.add("listening-sockets", stdout="")
    view = SystemView(make_root({}), fake_runner, allow_commands=False)
    with pytest.raises(CommandUnavailableError, match="disabled"):
        view.run("listening-sockets")
    assert fake_runner.calls == []


def test_real_runner_refuses_unknown_names_before_running_anything() -> None:
    with pytest.raises(CommandNotAllowedError):
        SubprocessRunner().run("bash -c 'id'")


def test_real_runner_reports_missing_binary() -> None:
    runner = SubprocessRunner(commands={"ghost": ("/nonexistent/bin/ghost",)})
    with pytest.raises(CommandUnavailableError, match="not installed"):
        runner.run("ghost")


posix_only = pytest.mark.skipif(sys.platform == "win32", reason="the real runner targets Linux")


@posix_only
def test_real_runner_captures_output_with_a_clean_environment() -> None:
    script = "import os; print(os.environ.get('LC_ALL'), os.environ.get('HOME'))"
    runner = SubprocessRunner(commands={"probe": (sys.executable, "-c", script)})
    result = runner.run("probe")
    assert result.ok
    assert result.stdout.strip() == "C None"  # LC_ALL forced, nothing else inherited


@posix_only
def test_real_runner_times_out() -> None:
    sleeper = (sys.executable, "-c", "import time; time.sleep(5)")
    runner = SubprocessRunner(commands={"sleep": sleeper}, timeout=0.5)
    with pytest.raises(CommandTimeoutError):
        runner.run("sleep")


# --------------------------------------------------------------- privileges


def test_is_root_true_for_euid_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "geteuid", lambda: 0, raising=False)
    assert privileges.is_root()


def test_is_root_false_for_normal_user(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "geteuid", lambda: 1000, raising=False)
    assert not privileges.is_root()


def test_is_root_false_without_euid(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delattr(os, "geteuid", raising=False)
    assert not privileges.is_root()
