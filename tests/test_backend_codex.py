from __future__ import annotations

import fcntl
import json
import os
import stat
from pathlib import Path

import pytest

from auth_picker.backends.base import Inconsistent, Unsupported
from auth_picker.backends.codex import CodexBackend
from auth_picker.errors import Conflict, LockTimeout
from tests.fakes import codex_auth


@pytest.fixture
def home(tmp_path: Path) -> Path:
    path = tmp_path / ".codex"
    path.mkdir()
    return path


def _log_in(home: Path, who: str, generation: int = 1) -> None:
    (home / "auth.json").write_text(json.dumps(codex_auth(who, generation), indent=2))


@pytest.mark.parametrize("mode", ["keyring", "auto", "ephemeral"])
def test_non_file_store_modes_are_refused(home: Path, mode: str) -> None:
    (home / "config.toml").write_text(f'cli_auth_credentials_store = "{mode}"\n')
    with pytest.raises(Unsupported, match=mode):
        CodexBackend(str(home)).check_supported()


def test_file_mode_and_default_are_supported(home: Path) -> None:
    CodexBackend(str(home)).check_supported()
    (home / "config.toml").write_text('cli_auth_credentials_store = "file"\n')
    CodexBackend(str(home)).check_supported()


def test_identity_comes_from_the_id_token(home: Path) -> None:
    _log_in(home, "alice")
    snap = CodexBackend(str(home)).read_live()
    assert snap is not None
    assert snap.identity.account_id == "ws-alice"
    assert snap.identity.subject_id == "user-alice"
    assert snap.identity.email == "alice@example.com"


def test_two_account_ids_that_disagree_are_inconsistent(home: Path) -> None:
    auth = codex_auth("alice")
    auth["tokens"]["account_id"] = "ws-someone-else"
    (home / "auth.json").write_text(json.dumps(auth))
    with pytest.raises(Inconsistent):
        CodexBackend(str(home)).read_live()


def test_api_key_logins_are_refused(home: Path) -> None:
    (home / "auth.json").write_text('{"OPENAI_API_KEY": "sk-test"}')
    with pytest.raises(Unsupported):
        CodexBackend(str(home)).read_live()


def test_a_half_written_file_is_not_logged_out(home: Path) -> None:
    (home / "auth.json").write_text(json.dumps(codex_auth("alice"))[:40])
    with pytest.raises(Inconsistent, match="being written"):
        CodexBackend(str(home)).read_live()


def test_install_writes_the_saved_login_verbatim(home: Path, tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _log_in(source, "bob")
    _log_in(home, "alice")
    backend = CodexBackend(str(home))
    target = CodexBackend(str(source)).read_live()
    assert target is not None
    with backend.locks(1) as held:
        backend.install(target.secret, backend.read_live(), held)
    assert json.loads((home / "auth.json").read_text()) == json.loads(
        (source / "auth.json").read_text()
    )


def test_install_refuses_a_file_that_changed(home: Path) -> None:
    _log_in(home, "alice")
    backend = CodexBackend(str(home))
    expect = backend.read_live()
    assert expect is not None
    _log_in(home, "alice", generation=2)
    rotated = (home / "auth.json").read_bytes()
    with backend.locks(1) as held, pytest.raises(Conflict):
        backend.install(expect.secret, expect, held)
    assert (home / "auth.json").read_bytes() == rotated


def test_install_into_a_logged_out_home_creates_an_owner_only_file(
    home: Path, tmp_path: Path
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _log_in(source, "bob")
    target = CodexBackend(str(source)).read_live()
    assert target is not None
    backend = CodexBackend(str(home))
    with backend.locks(1) as held:
        backend.install(target.secret, None, held)
    assert stat.S_IMODE(os.stat(home / "auth.json").st_mode) == 0o600


def test_locks_wait_for_codex(home: Path) -> None:
    _log_in(home, "alice")
    with open(home / "auth.json.lock", "w") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        with pytest.raises(LockTimeout, match="Codex"), CodexBackend(str(home)).locks(0.3):
            pass
