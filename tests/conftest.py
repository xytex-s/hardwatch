from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from fakes import FakeRunner

MakeRoot = Callable[[dict[str, str]], Path]


@pytest.fixture
def make_root(tmp_path: Path) -> MakeRoot:
    """Build a fake host filesystem: ``{"/etc/hostname": "lab-01\\n"}`` -> a root dir.

    The root sits one level inside tmp_path, so tests can put a "secret" file
    next to it (outside the root) and prove it cannot be reached.
    """

    def build(files: dict[str, str]) -> Path:
        root = tmp_path / "root"
        root.mkdir(exist_ok=True)
        for host_path, content in files.items():
            target = root.joinpath(*host_path.lstrip("/").split("/"))
            target.parent.mkdir(parents=True, exist_ok=True)
            # newline="" writes "\n" as-is. Without it, Windows turns every "\n" into
            # "\r\n" and the fake Linux host gets Windows line endings.
            target.write_text(content, encoding="utf-8", newline="")
        return root

    return build


@pytest.fixture
def fake_runner() -> FakeRunner:
    return FakeRunner()
