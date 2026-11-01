from __future__ import annotations

import os
import stat
from collections.abc import Iterator
from pathlib import Path

import pytest

from auth_picker import fsutil
from auth_picker.errors import Conflict, UnsafePath


@pytest.fixture
def no_umask() -> Iterator[None]:
    old = os.umask(0)
    try:
        yield
    finally:
        os.umask(old)


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.lstat().st_mode)


@pytest.mark.usefixtures("no_umask")
def test_private_write_is_owner_only_whatever_the_umask(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir(mode=0o755)
    target = state / "index.json"
    fsutil.write_private(str(target), b"{}")
    assert target.read_bytes() == b"{}"
    assert _mode(target) == 0o600
    assert _mode(state) == 0o700


def test_failed_private_write_keeps_the_old_file_and_no_temp(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "index.json"
    fsutil.write_private(str(target), b"old")

    def boom(*_args: object) -> None:
        raise OSError("disk full")

    monkeypatch.setattr("os.replace", boom)
    with pytest.raises(OSError, match="disk full"):
        fsutil.write_private(str(target), b"new")
    assert target.read_bytes() == b"old"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["index.json"]


def test_private_read_refuses_a_symlink(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.write_bytes(b"x")
    link = tmp_path / "link"
    link.symlink_to(real)
    with pytest.raises(UnsafePath):
        fsutil.read_private(str(link), 1024)
    assert fsutil.read_private(str(tmp_path / "missing"), 1024) is None


def test_secure_dir_refuses_a_symlink(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    with pytest.raises(UnsafePath):
        fsutil.secure_dir(str(link))


def test_secure_dir_refuses_an_ancestor_others_can_write(tmp_path: Path) -> None:
    shared = tmp_path / "shared"
    shared.mkdir()
    shared.chmod(0o777)
    try:
        with pytest.raises(UnsafePath):
            fsutil.secure_dir(str(shared / "state"))
    finally:
        shared.chmod(0o700)


def test_reads_refuse_oversized_files(tmp_path: Path) -> None:
    big = tmp_path / "big"
    big.write_bytes(b"x" * 2048)
    with pytest.raises(UnsafePath):
        fsutil.read_private(str(big), 1024)
    with pytest.raises(UnsafePath):
        fsutil.read_foreign(str(big), 1024)


@pytest.mark.usefixtures("no_umask")
def test_foreign_write_goes_through_symlink_and_keeps_mode(tmp_path: Path) -> None:
    dotfiles = tmp_path / "dotfiles"
    dotfiles.mkdir(mode=0o700)
    real = dotfiles / "claude.json"
    real.write_bytes(b'{"a": 1}')
    real.chmod(0o640)
    link = tmp_path / ".claude.json"
    link.symlink_to(real)

    read = fsutil.read_foreign(str(link), 1 << 20)
    assert read is not None
    fsutil.write_foreign(str(link), b'{"a": 2}', read)

    assert link.is_symlink()
    assert real.read_bytes() == b'{"a": 2}'
    assert _mode(real) == 0o640


def test_foreign_write_refuses_when_someone_else_wrote_first(tmp_path: Path) -> None:
    path = tmp_path / "auth.json"
    path.write_bytes(b"ours")
    read = fsutil.read_foreign(str(path), 1024)
    assert read is not None
    os.replace(_sibling(path, b"theirs"), path)  # another program's atomic write

    with pytest.raises(Conflict):
        fsutil.write_foreign(str(path), b"mine", read)
    assert path.read_bytes() == b"theirs"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["auth.json"]


def test_foreign_create_refuses_when_the_file_appeared(tmp_path: Path) -> None:
    path = tmp_path / "auth.json"
    path.write_bytes(b"theirs")
    with pytest.raises(Conflict):
        fsutil.write_foreign(str(path), b"mine", None)
    assert path.read_bytes() == b"theirs"


def test_foreign_create_when_absent(tmp_path: Path) -> None:
    path = tmp_path / "auth.json"
    fsutil.write_foreign(str(path), b"mine", None, new_mode=0o600)
    assert path.read_bytes() == b"mine"
    assert _mode(path) == 0o600


def test_touch(tmp_path: Path) -> None:
    path = tmp_path / ".credentials.json"
    assert not fsutil.touch(str(path))
    path.write_bytes(b"{}")
    os.utime(path, (0, 0))
    assert fsutil.touch(str(path))
    assert path.stat().st_mtime > 0
    assert path.read_bytes() == b"{}"


def _sibling(path: Path, data: bytes) -> Path:
    tmp = path.with_name(path.name + ".theirs")
    tmp.write_bytes(data)
    return tmp
