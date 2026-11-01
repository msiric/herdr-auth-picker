from __future__ import annotations

import hashlib
import json
import os
import platform
import subprocess
import time
import unicodedata
import uuid
from pathlib import Path

import pytest

from auth_picker.backends.base import Inconsistent, Unsupported, validate
from auth_picker.backends.claude import (
    ClaudeBackend,
    ClaudePaths,
    FileCredential,
    KeychainCredential,
    resolve_paths,
)
from auth_picker.errors import Conflict, LockTimeout
from tests.fakes import claude_blob, write_claude_config


@pytest.fixture
def home(tmp_path: Path) -> Path:
    (tmp_path / ".claude").mkdir()
    write_claude_config(tmp_path / ".claude.json", None)
    return tmp_path


def _paths(home: Path) -> ClaudePaths:
    return resolve_paths({"HOME": str(home), "USER": "alice"})


def _backend(home: Path) -> ClaudeBackend:
    paths = _paths(home)
    return ClaudeBackend(paths, store=FileCredential(paths.credentials_file))


def _log_in(home: Path, who: str, generation: int = 1, **machine: object) -> None:
    (home / ".claude" / ".credentials.json").write_text(
        json.dumps(claude_blob(who, generation, **machine))
    )
    config = json.loads((home / ".claude.json").read_text())
    write_claude_config(home / ".claude.json", who, projects=config["projects"])


def _install(backend: ClaudeBackend, secret_from: ClaudeBackend) -> None:
    target = secret_from.read_live()
    assert target is not None
    expect = backend.read_live()
    with backend.locks(1) as held:
        backend.install(target.secret, expect, held)


# -- where things are ---------------------------------------------------------


def test_paths_follow_claude_rules(tmp_path: Path) -> None:
    default = resolve_paths({"HOME": str(tmp_path), "USER": "alice"})
    assert default.keychain_service == "Claude Code-credentials"
    assert default.keychain_account == "alice"
    assert default.identity_file == str(tmp_path / ".claude.json")

    custom_dir = str(tmp_path / "cfg-é")
    custom = resolve_paths({"HOME": str(tmp_path), "USER": "a b", "CLAUDE_CONFIG_DIR": custom_dir})
    digest = hashlib.sha256(unicodedata.normalize("NFC", custom_dir).encode()).hexdigest()[:8]
    assert custom.keychain_service == f"Claude Code-credentials-{digest}"
    assert custom.keychain_account == "claude-code-user"
    assert custom.identity_file == os.path.join(custom_dir, ".claude.json")


def test_legacy_config_file_wins_when_present(home: Path) -> None:
    (home / ".claude" / ".config.json").write_text("{}")
    assert _paths(home).identity_file == str(home / ".claude" / ".config.json")


def test_secure_storage_override_is_refused(home: Path) -> None:
    with pytest.raises(Unsupported):
        resolve_paths({"HOME": str(home), "CLAUDE_SECURESTORAGE_CONFIG_DIR": "/x"})


# -- reading ------------------------------------------------------------------


def test_logged_out_reads_as_none(home: Path) -> None:
    assert _backend(home).read_live() is None


def test_snapshot_holds_the_account_and_not_the_machine(home: Path) -> None:
    _log_in(home, "alice", mcpOAuth={"server": {"token": "mcp"}})
    snap = _backend(home).read_live()
    assert snap is not None
    assert snap.identity.email == "alice@example.com"
    assert snap.identity.subject_id == "org-1-alice"
    assert snap.identity.plan == "max"
    saved = json.loads(snap.secret.reveal())
    assert set(saved["credentials"]) == {"claudeAiOauth", "trustedDeviceToken"}
    assert snap.refresh_expires_at is not None
    assert snap.refresh_expires_at > time.time()
    assert not validate(snap, time.time())
    reparsed = _backend(home).parse_secret(snap.secret)
    assert (reparsed.fingerprint, reparsed.cred_hash) == (snap.fingerprint, snap.cred_hash)


def test_unknown_credential_keys_are_refused(home: Path) -> None:
    _log_in(home, "alice", someNewAccountToken="x")
    with pytest.raises(Unsupported, match="someNewAccountToken"):
        _backend(home).read_live()


def test_a_credential_without_an_identity_is_inconsistent(home: Path) -> None:
    _log_in(home, "alice")
    write_claude_config(home / ".claude.json", None)
    with pytest.raises(Inconsistent):
        _backend(home).read_live()


# -- writing ------------------------------------------------------------------


def test_install_moves_the_account_and_keeps_the_machine(home: Path, tmp_path: Path) -> None:
    other = tmp_path / "other"
    (other / ".claude").mkdir(parents=True)
    write_claude_config(other / ".claude.json", None)
    _log_in(other, "bob", mcpOAuth={"server": {"token": "bobs-mcp"}})
    _log_in(home, "alice", mcpOAuth={"server": {"token": "alices-mcp"}})
    backend = _backend(home)

    _install(backend, _backend(other))

    after = backend.read_live()
    assert after is not None
    assert after.identity.email == "bob@example.com"
    stored = json.loads((home / ".claude" / ".credentials.json").read_text())
    assert stored["mcpOAuth"] == {"server": {"token": "alices-mcp"}}
    assert stored["claudeAiOauth"]["refreshToken"].startswith("sk-ant-ort01-bob")
    config = json.loads((home / ".claude.json").read_text())
    assert config["projects"] == {"/work": {"history": [1, 2, 3]}}


def test_install_refuses_a_store_that_changed_after_the_snapshot(home: Path) -> None:
    _log_in(home, "alice")
    backend = _backend(home)
    expect = backend.read_live()
    assert expect is not None
    # Claude rotated the token meanwhile; its config did not change.
    (home / ".claude" / ".credentials.json").write_text(json.dumps(claude_blob("alice", 2)))
    rotated = (home / ".claude" / ".credentials.json").read_bytes()
    with backend.locks(1) as held, pytest.raises(Conflict):
        backend.install(expect.secret, expect, held)
    assert (home / ".claude" / ".credentials.json").read_bytes() == rotated


def test_install_from_logged_out_refuses_if_a_login_appeared(home: Path) -> None:
    backend = _backend(home)
    _log_in(home, "alice")
    snap = backend.read_live()
    assert snap is not None
    with backend.locks(1) as held, pytest.raises(Conflict):
        backend.install(snap.secret, None, held)


def test_locks_wait_for_a_claude_refresh(home: Path) -> None:
    (home / ".claude" / ".oauth_refresh.lock").mkdir()  # a Claude process is refreshing
    with pytest.raises(LockTimeout, match="Claude Code is refreshing"), _backend(home).locks(0.3):
        pass
    assert not (home / ".claude" / ".storage-write.lock").exists()


# -- the real Keychain path, against a throwaway keychain ---------------------


@pytest.mark.skipif(platform.system() != "Darwin", reason="macOS keychain only")
def test_keychain_install_moves_the_credentials_file_mtime(home: Path, tmp_path: Path) -> None:
    keychain = str(tmp_path / "test.keychain-db")
    subprocess.run(["/usr/bin/security", "create-keychain", "-p", "t", keychain], check=True)
    subprocess.run(["/usr/bin/security", "unlock-keychain", "-p", "t", keychain], check=True)
    try:
        paths = _paths(home)
        store = KeychainCredential(f"auth-picker-test-{uuid.uuid4().hex[:8]}", "alice", keychain)
        backend = ClaudeBackend(paths, store=store)
        source_home = tmp_path / "source"
        (source_home / ".claude").mkdir(parents=True)
        write_claude_config(source_home / ".claude.json", None)
        _log_in(source_home, "bob")
        mcp_only = home / ".claude" / ".credentials.json"
        mcp_only.write_text('{"mcpOAuth": {}}')
        os.utime(mcp_only, (0, 0))

        assert backend.read_live() is None
        target = _backend(source_home).read_live()
        assert target is not None
        with backend.locks(1) as held:
            backend.install(target.secret, None, held)

        after = backend.read_live()
        assert after is not None
        assert after.fingerprint == target.fingerprint
        assert mcp_only.stat().st_mtime > 0
        assert mcp_only.read_text() == '{"mcpOAuth": {}}'
    finally:
        subprocess.run(["/usr/bin/security", "delete-keychain", keychain], check=False)
