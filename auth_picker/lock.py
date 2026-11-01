"""Exclusive locks on files, with a bounded wait.

flock locks belong to an open file description, so opening the same lock
file twice in one process and locking both would wait on ourselves for ever.
Locks are therefore re-entrant per path within a process: the nested ``with``
just counts. The plugin is single-threaded; this is not a thread lock.
"""

from __future__ import annotations

import fcntl
import os
import stat
import time
from types import TracebackType

from auth_picker.errors import LockTimeout, UnsafePath

_POLL_S = 0.05
_held: dict[str, tuple[int, int]] = {}  # path -> (fd, depth)


class FileLock:
    def __init__(self, path: str, timeout: float, what: str = "another operation") -> None:
        self.path = os.path.abspath(path)
        self.timeout = timeout
        self.what = what

    def __enter__(self) -> FileLock:
        held = _held.get(self.path)
        if held is not None:
            _held[self.path] = (held[0], held[1] + 1)
            return self
        try:
            fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        except OSError as exc:
            if os.path.islink(self.path):
                raise UnsafePath("symlink", f"{self.path} is a symlink") from None
            raise LockTimeout(
                "lock-open", f"cannot open lock {self.path}: {exc.strerror}"
            ) from None
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid():
            os.close(fd)
            raise UnsafePath("lock-file", f"{self.path} is not a regular file we own")
        deadline = time.monotonic() + self.timeout
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    os.close(fd)
                    raise LockTimeout(
                        "lock-timeout",
                        f"{self.what} has held the lock for over {self.timeout:g}s; "
                        "nothing was changed",
                    ) from None
                time.sleep(_POLL_S)
        _held[self.path] = (fd, 1)
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        fd, depth = _held[self.path]
        if depth > 1:
            _held[self.path] = (fd, depth - 1)
            return
        del _held[self.path]
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)
