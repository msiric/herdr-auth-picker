"""Taking other programs' locks, so we never write while they do.

Claude Code locks with directories, using the ``proper-lockfile`` scheme:
``mkdir`` takes the lock, the holder keeps the directory's mtime fresh, and
``rmdir`` releases it. A lock whose mtime is older than its stale period
belongs to a dead holder. Newer Codex takes an ``flock`` on a sidecar file.

``hold_all`` takes several such locks all-or-nothing. If any one is busy, it
releases what it holds and tries again after a short random wait. It never
waits while holding something, so it cannot deadlock with a program taking
the same locks in a different order.
"""

from __future__ import annotations

import contextlib
import fcntl
import os
import random
import stat
import time
from collections.abc import Iterator, Sequence
from typing import Protocol

from auth_picker.errors import LockTimeout, UnsafePath


class TryLock(Protocol):
    path: str

    def try_acquire(self) -> bool: ...
    def refresh(self) -> None: ...
    def release(self) -> None: ...


class DirLock:
    """A proper-lockfile style lock directory."""

    def __init__(self, path: str, stale_s: float) -> None:
        self.path = path
        self.stale_s = stale_s
        self._held = False

    def try_acquire(self) -> bool:
        for _ in range(2):
            try:
                os.mkdir(self.path, 0o700)
            except FileExistsError:
                if not self._break_if_abandoned():
                    return False
                continue
            self._held = True
            return True
        return False

    def _break_if_abandoned(self) -> bool:
        """Remove a lock whose holder died, as its owner would. True if removed."""
        try:
            st = os.lstat(self.path)
        except FileNotFoundError:
            return True
        if not stat.S_ISDIR(st.st_mode):
            raise UnsafePath("lock-shape", f"{self.path} exists but is not a lock directory")
        # Twice the stale period: stricter than the owner itself, never quicker.
        if time.time() - st.st_mtime <= 2 * self.stale_s:
            return False
        try:
            os.rmdir(self.path)
        except FileNotFoundError:
            return True
        except OSError:
            return False
        return True

    def refresh(self) -> None:
        if self._held:
            os.utime(self.path)

    def release(self) -> None:
        if self._held:
            self._held = False
            with contextlib.suppress(FileNotFoundError):
                os.rmdir(self.path)


class Flock:
    """An flock on a sidecar file (Codex's ``auth.json.lock``)."""

    def __init__(self, path: str) -> None:
        self.path = path
        self._fd: int | None = None

    def try_acquire(self) -> bool:
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(fd)
            return False
        self._fd = fd
        return True

    def refresh(self) -> None:
        return None

    def release(self) -> None:
        if self._fd is not None:
            fd, self._fd = self._fd, None
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)


class Held:
    """The locks while held. ``refresh()`` keeps directory locks from going stale."""

    def __init__(self, locks: Sequence[TryLock]) -> None:
        self.locks = locks

    def refresh(self) -> None:
        for lock in self.locks:
            lock.refresh()


@contextlib.contextmanager
def hold_all(locks: Sequence[TryLock], timeout: float, busy: str) -> Iterator[Held]:
    """Hold every lock in ``locks``, or raise LockTimeout saying ``busy``."""
    deadline = time.monotonic() + timeout
    while True:
        taken: list[TryLock] = []
        try:
            for lock in locks:
                if not lock.try_acquire():
                    break
                taken.append(lock)
        except BaseException:
            for lock in reversed(taken):
                lock.release()
            raise
        if len(taken) == len(locks):
            break
        for lock in reversed(taken):
            lock.release()
        if time.monotonic() >= deadline:
            raise LockTimeout("busy", f"{busy}; nothing was changed, try again shortly")
        time.sleep(random.uniform(0.05, 0.15))  # noqa: S311 - jitter, not security
    try:
        yield Held(locks)
    finally:
        for lock in reversed(locks):
            lock.release()
