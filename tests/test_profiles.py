from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from auth_picker.backends.base import Snapshot
from auth_picker.profiles import CorruptIndex, ProfileError, Profiles
from auth_picker.redact import Sensitive
from auth_picker.secretstore import FileStore
from tests.fakes import claude_secret, codex_secret, make_backends


@pytest.fixture
def profiles(tmp_path: Path) -> Profiles:
    return Profiles(
        str(tmp_path / "state"), FileStore(str(tmp_path / "secrets")), make_backends(tmp_path)
    )


def claude(profiles: Profiles, who: str, generation: int = 1) -> Snapshot:
    return profiles.backends["claude"].parse_secret(Sensitive(claude_secret(who, generation)))


def test_create_find_and_read_back(profiles: Profiles) -> None:
    work = profiles.create("Work", claude(profiles, "alice"))
    profiles.create("Spare", claude(profiles, "bob"))
    codex = profiles.backends["codex"].parse_secret(Sensitive(codex_secret("alice")))
    profiles.create("Work", codex)  # the same name is fine for another kind

    assert [p.label for p in profiles.of_kind("claude")] == ["Work", "Spare"]
    assert profiles.find("claude", "work").id == work.id
    assert profiles.find("claude", work.id[:8]).id == work.id
    secret, snapshot = profiles.secret(work)
    assert secret == claude(profiles, "alice").secret
    assert snapshot.identity.email == "alice@example.com"


def test_index_holds_no_secrets_and_is_owner_only(profiles: Profiles) -> None:
    profiles.create("Work", claude(profiles, "alice"))
    text = Path(profiles.index_path).read_text()
    assert "sk-ant" not in text
    assert stat.S_IMODE(os.stat(profiles.index_path).st_mode) == 0o600


@pytest.mark.parametrize(
    ("who", "label", "code"),
    [("alice", "Other", "duplicate"), ("bob", "WORK", "label-taken"), ("bob", "a\x1bb", "label")],
)
def test_create_refuses(profiles: Profiles, who: str, label: str, code: str) -> None:
    profiles.create("Work", claude(profiles, "alice"))
    with pytest.raises(ProfileError) as caught:
        profiles.create(label, claude(profiles, who))
    assert caught.value.code == code


def test_update_keeps_the_previous_generation(profiles: Profiles) -> None:
    work = profiles.create("Work", claude(profiles, "alice"))
    first = claude(profiles, "alice")
    second = claude(profiles, "alice", generation=2)
    updated = profiles.update_secret(work, second)

    assert profiles.store.get(updated.key) == second.secret
    assert profiles.store.get(updated.prev_key) == first.secret
    assert updated.holds(cred_hash=first.cred_hash)
    assert updated.holds(refresh_hash=second.refresh_hash)


def test_update_refuses_another_account(profiles: Profiles) -> None:
    work = profiles.create("Work", claude(profiles, "alice"))
    with pytest.raises(ProfileError, match="not Work's account"):
        profiles.update_secret(work, claude(profiles, "bob"))
    assert profiles.secret(work)[0] == claude(profiles, "alice").secret


def test_a_tampered_secret_is_detected(profiles: Profiles) -> None:
    work = profiles.create("Work", claude(profiles, "alice"))
    profiles.store.put(work.key, claude(profiles, "alice", generation=9).secret)
    with pytest.raises(ProfileError, match="does not match"):
        profiles.secret(work)


def test_rename_and_delete(profiles: Profiles) -> None:
    work = profiles.create("Work", claude(profiles, "alice"))
    profiles.update_secret(work, claude(profiles, "alice", generation=2))
    renamed = profiles.rename(work, "Day job")
    assert profiles.get(work.id).label == "Day job"
    profiles.delete(renamed)
    assert profiles.all() == []
    assert profiles.store.keys() == []


def test_a_damaged_index_is_never_overwritten(profiles: Profiles) -> None:
    profiles.create("Work", claude(profiles, "alice"))
    Path(profiles.index_path).write_text('{"schema": 1, "profiles": [{"id": "x"}]}')
    with pytest.raises(CorruptIndex):
        profiles.create("Spare", claude(profiles, "bob"))
    assert json.loads(Path(profiles.index_path).read_text())["profiles"] == [{"id": "x"}]


def test_a_crash_before_the_index_write_leaves_only_an_orphan(
    profiles: Profiles, monkeypatch: pytest.MonkeyPatch
) -> None:
    def crash(*_args: object) -> None:
        raise OSError("power cut")

    monkeypatch.setattr(Profiles, "_write", crash)
    with pytest.raises(OSError, match="power cut"):
        profiles.create("Work", claude(profiles, "alice"))
    monkeypatch.undo()
    assert profiles.all() == []
    assert len(profiles.orphans()) == 1
