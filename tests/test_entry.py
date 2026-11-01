"""The herdr entry point must not be steerable through the environment."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from auth_picker import __version__
from tests.conftest import ROOT

MAIN = str(ROOT / "main.py")


def _run(argv: list[str], env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, capture_output=True, text=True, env=env, timeout=30, check=False)


def test_runs_isolated() -> None:
    result = _run([sys.executable, "-I", MAIN, "--version"])
    assert result.returncode == 0, result.stderr
    assert __version__ in result.stdout


def test_pythonpath_cannot_shadow_modules_without_isolation(tmp_path: Path) -> None:
    # A hand-written tab-bar command may forget -I. Anything on PYTHONPATH that
    # would shadow our package or a stdlib module we import must be ignored.
    (tmp_path / "auth_picker").mkdir()
    (tmp_path / "auth_picker" / "__init__.py").write_text("raise SystemExit('shadowed package')\n")
    (tmp_path / "argparse.py").write_text("raise SystemExit('shadowed stdlib')\n")
    env = {"PYTHONPATH": str(tmp_path), "PATH": "/usr/bin:/bin"}
    result = _run([sys.executable, MAIN, "--version"], env=env)
    assert result.returncode == 0, result.stderr
    assert "shadowed" not in result.stdout + result.stderr


LAUNCHER = str(ROOT / "bin" / "auth-picker")
OLD_PYTHON = "#!/bin/sh\n# pretends to be Apple's Python 3.9\nexit 1\n"


def _fake_python(directory: Path, name: str = "python3") -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    fake = directory / name
    fake.write_text(OLD_PYTHON)
    fake.chmod(0o755)
    return fake


def test_launcher_skips_a_python_that_is_too_old(tmp_path: Path) -> None:
    _fake_python(tmp_path / "old")
    real = str(Path(sys.executable).parent)
    env = {"PATH": f"{tmp_path / 'old'}:{real}:/usr/bin:/bin"}
    result = _run(["/bin/sh", LAUNCHER, "--version"], env=env)
    assert result.returncode == 0, result.stderr
    assert __version__ in result.stdout


@pytest.mark.parametrize("given", ["python3", "old"])
def test_launcher_refuses_a_bad_explicit_python(tmp_path: Path, given: str) -> None:
    value = str(_fake_python(tmp_path / "old")) if given == "old" else given
    env = {"PATH": "/usr/bin:/bin", "AUTH_PICKER_PYTHON": value}
    result = _run(["/bin/sh", LAUNCHER, "--version"], env=env)
    assert result.returncode == 2
    assert "AUTH_PICKER_PYTHON" in result.stderr
