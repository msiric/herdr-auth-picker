from __future__ import annotations

import base64
import json
import os
import platform
import subprocess
import uuid
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Any

import pytest

from auth_picker import proc
from auth_picker.redact import Sensitive
from auth_picker.secretstore import FileStore, KeychainStore, SecretStore, check_key
from auth_picker.secretstore.keychain import KeychainError, write_password

SECURITY = "/usr/bin/security"
SECRET = Sensitive(bytes(range(256)) + '{"t": "quote\\" ünï"}'.encode())
on_macos = pytest.mark.skipif(platform.system() != "Darwin", reason="macOS keychain only")


@pytest.mark.parametrize("key", ["profile:2f1c-ab", "undo:claude", "tx:abc:pre", "rescue:r1:0"])
def test_valid_keys(key: str) -> None:
    assert check_key(key) == key


@pytest.mark.parametrize(
    "key", ["profile", 'profile:"x"', "profile:a b", "profile:a\nb", "Profile:x", "profile::x"]
)
def test_invalid_keys(key: str) -> None:
    with pytest.raises(ValueError, match="invalid secret key"):
        check_key(key)


@pytest.fixture
def keychain(tmp_path: Path) -> Iterator[KeychainStore]:
    """A throwaway keychain file; the login keychain is never touched."""
    path = str(tmp_path / "test.keychain-db")
    subprocess.run([SECURITY, "create-keychain", "-p", "test", path], check=True)
    subprocess.run([SECURITY, "unlock-keychain", "-p", "test", path], check=True)
    try:
        yield KeychainStore(f"auth-picker-test-{uuid.uuid4().hex[:8]}", keychain=path)
    finally:
        subprocess.run([SECURITY, "delete-keychain", path], check=False)


@pytest.fixture(params=["file", pytest.param("keychain", marks=on_macos)])
def store(request: pytest.FixtureRequest, tmp_path: Path) -> SecretStore:
    if request.param == "file":
        return FileStore(str(tmp_path / "secrets"))
    keychain_store: KeychainStore = request.getfixturevalue("keychain")
    return keychain_store


def test_round_trip_is_exact(store: SecretStore) -> None:
    store.put("profile:a", SECRET)
    assert store.get("profile:a") == SECRET


def test_put_replaces(store: SecretStore) -> None:
    store.put("profile:a", Sensitive(b"first"))
    store.put("profile:a", Sensitive(b"second"))
    assert store.get("profile:a") == Sensitive(b"second")


def test_missing_and_delete(store: SecretStore) -> None:
    assert store.get("profile:none") is None
    store.put("profile:a", Sensitive(b"x"))
    assert store.delete("profile:a") is True
    assert store.delete("profile:a") is False
    assert store.get("profile:a") is None


def test_keys_lists_only_this_store(store: SecretStore) -> None:
    store.put("profile:a", Sensitive(b"x"))
    store.put("undo:claude", Sensitive(b"y"))
    assert store.keys() == ["profile:a", "undo:claude"]


def test_file_secrets_are_owner_only(tmp_path: Path) -> None:
    store = FileStore(str(tmp_path / "secrets"))
    store.put("profile:a", Sensitive(b"x"))
    assert os.stat(tmp_path / "secrets" / "profile:a.secret").st_mode & 0o777 == 0o600
    assert os.stat(tmp_path / "secrets").st_mode & 0o777 == 0o700


@on_macos
def test_secret_never_reaches_any_argv(
    keychain: KeychainStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[Sequence[str]] = []
    real_run = proc.run

    def recording_run(argv: Sequence[str], **kwargs: Any) -> proc.Result:
        seen.append(list(argv))
        return real_run(argv, **kwargs)

    monkeypatch.setattr(proc, "run", recording_run)
    keychain.put("profile:a", SECRET)
    assert keychain.get("profile:a") == SECRET

    raw = SECRET.reveal()
    encoded = base64.b64encode(raw)
    forms = [raw.hex(), encoded.decode(), encoded.hex()]
    argv_text = "\n".join(" ".join(argv) for argv in seen)
    assert seen
    assert not [form for form in forms if form in argv_text]
    assert not any("-w" in argv and "add-generic-password" in argv for argv in seen)


@on_macos
def test_foreign_item_in_unexpected_format_is_an_error(keychain: KeychainStore) -> None:
    write_password(
        keychain.service, "profile:a", Sensitive(b"not base64!"), keychain=keychain.keychain
    )
    with pytest.raises(KeychainError):
        keychain.get("profile:a")


@on_macos
def test_large_values_are_split_into_commands_that_fit(
    keychain: KeychainStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    from auth_picker.secretstore.keychain import MAX_COMMAND_BYTES  # noqa: PLC0415

    sizes: list[int] = []
    real_run = proc.run

    def recording_run(argv: Sequence[str], **kwargs: Any) -> proc.Result:
        if kwargs.get("input") is not None:
            sizes.append(len(kwargs["input"]))
        return real_run(argv, **kwargs)

    monkeypatch.setattr(proc, "run", recording_run)
    big = Sensitive(os.urandom(10_000))
    keychain.put("profile:big", big)
    assert keychain.get("profile:big") == big
    assert sizes
    assert max(sizes) <= MAX_COMMAND_BYTES
    assert keychain.keys() == ["profile:big"]  # parts stay out of sight

    smaller = Sensitive(b"x" * 3000)
    keychain.put("profile:big", smaller)
    assert keychain.get("profile:big") == smaller
    assert keychain.delete("profile:big")
    raw = subprocess.run(
        [SECURITY, "dump-keychain", keychain.keychain or ""], capture_output=True, check=True
    ).stdout
    assert keychain.service.encode() not in raw  # every part went with it


@on_macos
def test_an_oversized_write_is_refused_before_anything_runs(
    keychain: KeychainStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[Sequence[str]] = []
    monkeypatch.setattr(proc, "run", lambda argv, **_k: calls.append(argv))
    with pytest.raises(KeychainError, match="too large"):
        write_password(keychain.service, "x", Sensitive(b"y" * 3000), keychain.keychain)
    assert calls == []


@on_macos
def test_a_crash_before_the_manifest_keeps_the_old_value(
    keychain: KeychainStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    old = Sensitive(os.urandom(5000))
    keychain.put("profile:a", old)
    real = KeychainStore._put_raw

    def crash_on_manifest(self: KeychainStore, account: str, data: bytes) -> None:
        if account == "profile:a":
            raise OSError("power cut")
        real(self, account, data)

    monkeypatch.setattr(KeychainStore, "_put_raw", crash_on_manifest)
    with pytest.raises(OSError, match="power cut"):
        keychain.put("profile:a", Sensitive(os.urandom(5000)))
    monkeypatch.undo()
    assert keychain.get("profile:a") == old


@on_macos
def test_values_stored_whole_by_earlier_versions_still_read(keychain: KeychainStore) -> None:
    write_password(
        keychain.service,
        "profile:old",
        Sensitive(base64.b64encode(b'{"schema":1}')),
        keychain=keychain.keychain,
    )
    assert keychain.get("profile:old") == Sensitive(b'{"schema":1}')


@on_macos
def test_a_damaged_item_can_still_be_deleted(keychain: KeychainStore) -> None:
    write_password(
        keychain.service, "profile:bad", Sensitive(b"not base64!"), keychain=keychain.keychain
    )
    assert keychain.delete("profile:bad")
    assert keychain.keys() == []


def test_each_state_dir_has_its_own_id(tmp_path: Path) -> None:
    from auth_picker.secretstore import install_id  # noqa: PLC0415

    first = install_id(str(tmp_path / "a"))
    assert first == install_id(str(tmp_path / "a"))
    assert first != install_id(str(tmp_path / "b"))
    assert len(first) == 16


def test_only_this_installs_keys_are_adopted_from_the_old_shared_service(tmp_path: Path) -> None:
    from auth_picker.secretstore import adopt_legacy  # noqa: PLC0415

    legacy = FileStore(str(tmp_path / "legacy"))
    legacy.put("profile:mine", Sensitive(b"mine"))
    legacy.put("profile:someone-elses", Sensitive(b"theirs"))
    store = FileStore(str(tmp_path / "new"))
    assert adopt_legacy(store, legacy, ["profile:mine", "undo:claude"]) == (["profile:mine"], [])
    assert store.get("profile:mine") == Sensitive(b"mine")
    assert legacy.keys() == ["profile:someone-elses"]


def test_two_processes_creating_the_install_id_agree(tmp_path: Path) -> None:
    from auth_picker.fsutil import create_private  # noqa: PLC0415
    from auth_picker.secretstore import install_id  # noqa: PLC0415

    state = tmp_path / "state"
    assert create_private(str(state / "install-id"), b"0123456789abcdef")  # the other one won
    assert not create_private(str(state / "install-id"), b"fedcba9876543210")
    assert install_id(str(state)) == "0123456789abcdef"


@on_macos
def test_upgrading_from_rc1_moves_journals_and_rescues_too(
    keychain: KeychainStore, tmp_path: Path
) -> None:
    from auth_picker.app import _adopt_legacy  # noqa: PLC0415
    from auth_picker.journal import JournalStore  # noqa: PLC0415
    from auth_picker.profiles import Profiles  # noqa: PLC0415
    from auth_picker.switch import store_tag  # noqa: PLC0415
    from tests.fakes import make_backends  # noqa: PLC0415

    state = tmp_path / "state"
    new = KeychainStore(keychain.service + "-new", keychain=keychain.keychain)
    backends = make_backends(tmp_path)
    profiles = Profiles(str(state), new, backends)
    journals = JournalStore(str(state), new)
    keychain.put("tx:abc:pre", Sensitive(b"pre-image"))
    keychain.put("rescue:r1:0", Sensitive(b"kept"))
    (state / "tx").mkdir(parents=True)
    (state / "tx" / "claude.json").write_text(
        json.dumps(
            {
                "txid": "abc",
                "kind": "claude",
                "phase": "installing",
                "target_label": "B",
                "target_fingerprint": "f",
                "target_components": {},
                "pre_fingerprint": "p",
            }
        )
    )
    (state / "rescue").mkdir()
    (state / "rescue" / "r1.json").write_text(
        json.dumps(
            {
                "rid": "r1",
                "kind": "claude",
                "reason": "x",
                "created_at": 0,
                "kept": [{"key": "rescue:r1:0", "what": "w", "describe": "", "fingerprint": None}],
            }
        )
    )

    _adopt_legacy(str(state), new, profiles, journals, backends, legacy=keychain)

    assert new.get("tx:abc:pre") == Sensitive(b"pre-image")
    assert new.get("rescue:r1:0") == Sensitive(b"kept")
    assert keychain.keys() == []
    moved = journals.current(store_tag(backends["claude"]))
    assert moved is not None
    assert moved.txid == "abc"
    assert not (state / "tx" / "claude.json").exists()


@on_macos
def test_a_migration_that_fails_part_way_loses_track_of_nothing(
    keychain: KeychainStore, tmp_path: Path
) -> None:
    from auth_picker.app import _adopt_legacy  # noqa: PLC0415
    from auth_picker.journal import JournalStore  # noqa: PLC0415
    from auth_picker.profiles import Profiles  # noqa: PLC0415
    from auth_picker.switch import store_tag  # noqa: PLC0415
    from tests.fakes import make_backends  # noqa: PLC0415

    class Flaky(KeychainStore):
        """The old service, refusing one item the first time."""

        refused = False

        def get(self, key: str) -> Sensitive | None:
            if key == "tx:abc:pre" and not Flaky.refused:
                Flaky.refused = True
                raise KeychainError("keychain-read", "locked")
            return super().get(key)

    state = tmp_path / "state"
    new = KeychainStore(keychain.service + "-new", keychain=keychain.keychain)
    legacy = Flaky(keychain.service, keychain=keychain.keychain)
    backends = make_backends(tmp_path)
    profiles = Profiles(str(state), new, backends)
    journals = JournalStore(str(state), new)
    keychain.put("tx:abc:pre", Sensitive(b"pre-image"))
    (state / "tx").mkdir(parents=True)
    (state / "tx" / "claude.json").write_text(
        json.dumps(
            {
                "txid": "abc",
                "kind": "claude",
                "phase": "installing",
                "target_label": "B",
                "target_fingerprint": "f",
                "target_components": {},
                "pre_fingerprint": "p",
            }
        )
    )

    assert _adopt_legacy(str(state), new, profiles, journals, backends, legacy=legacy) == [
        "tx:abc:pre"
    ]
    assert (state / "tx" / "claude.json").exists()  # not renamed: its pre-image did not move
    assert not (state / "keychain-per-install").exists()

    assert _adopt_legacy(str(state), new, profiles, journals, backends, legacy=legacy) == []
    assert new.get("tx:abc:pre") == Sensitive(b"pre-image")
    assert journals.current(store_tag(backends["claude"])) is not None
    assert (state / "keychain-per-install").exists()
