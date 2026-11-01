"""Filesystem primitives.

Two kinds of file, with different rules:

- **Ours** (state, index, journal): in directories we create 0700 and verify.
  Opened without following symlinks; written atomically and durably.
- **Foreign** (``~/.claude.json``, ``auth.json``): owned by the user but
  written by other programs at any moment. We follow a symlink to its target
  (dotfile managers link these), keep the target's mode, and write only if the
  file is still the revision we read.

Every write is: temp file in the same directory → fsync → rename → fsync of
the directory. On macOS, fsync does not reach the disk; F_FULLFSYNC does.
"""

from __future__ import annotations

import contextlib
import errno
import fcntl
import os
import stat
import tempfile
from dataclasses import dataclass, field

from auth_picker.errors import Conflict, UnsafePath


@dataclass(frozen=True)
class Version:
    """One revision of a file. Any rewrite or rename produces a new one."""

    dev: int
    ino: int
    size: int
    mtime_ns: int

    @classmethod
    def of(cls, st: os.stat_result) -> Version:
        return cls(st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns)


@dataclass(frozen=True)
class ForeignFile:
    """A foreign file as read: where it really lives, what it held, which revision."""

    path: str
    target: str
    data: bytes = field(repr=False)
    version: Version
    mode: int


def _full_fsync(fd: int) -> None:
    full = getattr(fcntl, "F_FULLFSYNC", None)
    if full is not None:
        try:
            fcntl.fcntl(fd, full)
        except OSError:
            pass
        else:
            return
    os.fsync(fd)


def fsync_dir(path: str) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        _full_fsync(fd)
    finally:
        os.close(fd)


def _ancestors_safe(path: str) -> None:
    """Refuse a path any other user could swap out from under us.

    Each ancestor must be owned by us or root, and must not be writable by
    group or others unless it is sticky (as /tmp is).
    """
    uid = os.getuid()
    current = os.path.dirname(os.path.abspath(path))
    while True:
        st = os.stat(current)
        if st.st_uid not in (uid, 0):
            raise UnsafePath("ancestor-owner", f"{current} is owned by another user")
        if st.st_mode & 0o022 and not st.st_mode & stat.S_ISVTX:
            raise UnsafePath("ancestor-mode", f"{current} is writable by other users")
        parent = os.path.dirname(current)
        if parent == current:
            return
        current = parent


def secure_dir(path: str) -> str:
    """Create (if missing) and verify a directory only we can use. Returns it."""
    os.makedirs(path, mode=0o700, exist_ok=True)
    st = os.lstat(path)
    if not stat.S_ISDIR(st.st_mode):
        raise UnsafePath("not-a-dir", f"{path} is not a directory (or is a symlink)")
    if st.st_uid != os.getuid():
        raise UnsafePath("dir-owner", f"{path} is owned by another user")
    if stat.S_IMODE(st.st_mode) & 0o077:
        os.chmod(path, 0o700)
    _ancestors_safe(path)
    return path


def _read_fd(fd: int, path: str, max_bytes: int) -> tuple[bytes, os.stat_result]:
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode):
        raise UnsafePath("not-a-file", f"{path} is not a regular file")
    if st.st_uid != os.getuid():
        raise UnsafePath("file-owner", f"{path} is owned by another user")
    if st.st_size > max_bytes:
        raise UnsafePath("too-large", f"{path} is larger than {max_bytes} bytes")
    chunks: list[bytes] = []
    remaining = max_bytes + 1
    while remaining > 0:
        chunk = os.read(fd, min(remaining, 1 << 16))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    data = b"".join(chunks)
    if len(data) > max_bytes:
        raise UnsafePath("too-large", f"{path} grew past {max_bytes} bytes while reading")
    return data, st


def _open_nofollow(path: str) -> int | None:
    try:
        return os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        return None
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise UnsafePath("symlink", f"{path} is a symlink") from None
        raise


def read_private(path: str, max_bytes: int) -> bytes | None:
    """Read one of our files. None when it does not exist."""
    fd = _open_nofollow(path)
    if fd is None:
        return None
    try:
        return _read_fd(fd, path, max_bytes)[0]
    finally:
        os.close(fd)


def _write_temp(directory: str, name: str, data: bytes, mode: int) -> str:
    fd, tmp = tempfile.mkstemp(prefix=f".{name}.", suffix=".tmp", dir=directory)
    try:
        os.fchmod(fd, mode)
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        _full_fsync(fd)
    except BaseException:
        os.close(fd)
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise
    os.close(fd)
    return tmp


def write_private(path: str, data: bytes, mode: int = 0o600) -> None:
    """Atomically and durably replace one of our files."""
    directory = secure_dir(os.path.dirname(os.path.abspath(path)))
    tmp = _write_temp(directory, os.path.basename(path), data, mode)
    try:
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise
    fsync_dir(directory)


def create_private(path: str, data: bytes, mode: int = 0o600) -> bool:
    """Create one of our files only if it does not exist. False if it already did."""
    directory = secure_dir(os.path.dirname(os.path.abspath(path)))
    tmp = _write_temp(directory, os.path.basename(path), data, mode)
    try:
        os.link(tmp, path)  # fails if the name exists: atomic create-if-absent
    except FileExistsError:
        return False
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
    fsync_dir(directory)
    return True


def remove_private(path: str) -> None:
    with contextlib.suppress(FileNotFoundError):
        os.unlink(path)
        fsync_dir(os.path.dirname(os.path.abspath(path)))


def read_foreign(path: str, max_bytes: int) -> ForeignFile | None:
    """Read a file another program owns, through any symlink. None if absent."""
    target = os.path.realpath(path)
    fd = _open_nofollow(target)
    if fd is None:
        return None
    try:
        data, st = _read_fd(fd, target, max_bytes)
    finally:
        os.close(fd)
    return ForeignFile(path, target, data, Version.of(st), stat.S_IMODE(st.st_mode))


def _current_version(target: str) -> Version | None:
    try:
        return Version.of(os.lstat(target))
    except FileNotFoundError:
        return None


def write_foreign(
    path: str, data: bytes, expect: ForeignFile | None, new_mode: int = 0o600
) -> Version:
    """Write a foreign file, only if it is still the revision we read.

    ``expect`` is what we read before (None: we saw no file, so create it only
    if it still does not exist). Raises Conflict when someone else wrote it in
    the meantime; nothing is changed then.
    """
    target = expect.target if expect is not None else os.path.realpath(path)
    directory = os.path.dirname(target)
    _ancestors_safe(target)
    mode = expect.mode if expect is not None else new_mode
    tmp = _write_temp(directory, os.path.basename(target), data, mode)
    try:
        if expect is None:
            # link() fails if the name exists: create-if-absent, atomically.
            try:
                os.link(tmp, target)
            except FileExistsError:
                raise Conflict("appeared", f"{path} was created by another program") from None
            os.unlink(tmp)
        else:
            if _current_version(target) != expect.version:
                raise Conflict("changed", f"{path} was changed by another program")
            os.replace(tmp, target)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise
    fsync_dir(directory)
    version = _current_version(target)
    if version is None:  # pragma: no cover - deleted in the instant after our rename
        raise Conflict("vanished", f"{path} disappeared right after it was written")
    return version


def touch(path: str) -> bool:
    """Move a file's modification time to now, if it exists. True if it did."""
    try:
        os.utime(path)
    except FileNotFoundError:
        return False
    return True
