from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

import pytest

from auth_picker.errors import LockTimeout, UnsafePath
from auth_picker.lock import FileLock

HOLDER = """
import fcntl, sys, time
handle = open(sys.argv[1], "w")
fcntl.flock(handle, fcntl.LOCK_EX)
print("held", flush=True)
time.sleep(float(sys.argv[2]))
"""


def _hold(path: Path, seconds: float) -> subprocess.Popen[str]:
    proc = subprocess.Popen(
        [sys.executable, "-c", HOLDER, str(path), str(seconds)],
        stdout=subprocess.PIPE,
        text=True,
    )
    assert proc.stdout is not None
    assert proc.stdout.readline().strip() == "held"
    return proc


def test_reentrant_within_a_process(tmp_path: Path) -> None:
    path = tmp_path / "lock"
    with FileLock(str(path), timeout=1), FileLock(str(path), timeout=1):
        pass
    with FileLock(str(path), timeout=1):  # released properly
        pass


def test_waits_a_bounded_time_for_another_process(tmp_path: Path) -> None:
    path = tmp_path / "lock"
    holder = _hold(path, 10)
    try:
        started = time.monotonic()
        with pytest.raises(LockTimeout), FileLock(str(path), timeout=0.3):
            pass
        assert time.monotonic() - started < 2
    finally:
        holder.kill()
        holder.wait()
    with FileLock(str(path), timeout=1):  # free once the holder is gone
        pass


def test_takes_the_lock_once_another_process_lets_go(tmp_path: Path) -> None:
    path = tmp_path / "lock"
    holder = _hold(path, 0.3)
    try:
        with FileLock(str(path), timeout=5):
            pass
    finally:
        holder.wait()


def test_refuses_a_symlinked_lock_file(tmp_path: Path) -> None:
    real = tmp_path / "elsewhere"
    real.write_text("")
    link = tmp_path / "lock"
    link.symlink_to(real)
    with pytest.raises(UnsafePath), FileLock(str(link), timeout=1):
        pass
