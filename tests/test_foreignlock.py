from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from auth_picker.errors import LockTimeout, UnsafePath
from auth_picker.foreignlock import DirLock, hold_all


def test_holds_and_releases_lock_directories(tmp_path: Path) -> None:
    a, b = tmp_path / "a.lock", tmp_path / "b.lock"
    with hold_all([DirLock(str(a), 10), DirLock(str(b), 10)], 1, "busy"):
        assert a.is_dir()
        assert b.is_dir()
    assert not a.exists()
    assert not b.exists()


def test_busy_lock_times_out_without_holding_the_others(tmp_path: Path) -> None:
    free, busy = tmp_path / "free.lock", tmp_path / "busy.lock"
    busy.mkdir()  # someone else holds it, and keeps it fresh
    with (
        pytest.raises(LockTimeout, match="Claude is busy"),
        hold_all([DirLock(str(free), 10), DirLock(str(busy), 10)], 0.3, "Claude is busy"),
    ):
        pass
    assert not free.exists()
    assert busy.is_dir()


def test_abandoned_lock_is_broken_only_after_twice_its_stale_period(tmp_path: Path) -> None:
    lock = tmp_path / "x.lock"
    lock.mkdir()
    old = time.time() - 15
    os.utime(lock, (old, old))
    with pytest.raises(LockTimeout), hold_all([DirLock(str(lock), 10)], 0.2, "busy"):
        pass
    old = time.time() - 25
    os.utime(lock, (old, old))
    with hold_all([DirLock(str(lock), 10)], 0.2, "busy"):
        assert lock.is_dir()


def test_a_file_where_a_lock_directory_should_be_is_refused(tmp_path: Path) -> None:
    lock = tmp_path / "x.lock"
    lock.write_text("")
    with pytest.raises(UnsafePath), hold_all([DirLock(str(lock), 10)], 0.2, "busy"):
        pass
