from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import pytest

from auth_picker import cli, migrate
from auth_picker.profiles import Profiles
from auth_picker.secretstore import FileStore
from tests.fakes import claude_account, claude_blob, codex_auth, make_backends


def _legacy(root: Path, kind: str, slug: str, payload: dict[str, Any], label: str) -> Path:
    directory = root / "profiles" / kind
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{slug}.json"
    path.write_text(json.dumps({"kind": kind, "slug": slug, "label": label, "payload": payload}))
    return path


def _claude_payload(who: str, generation: int = 1, **machine: Any) -> dict[str, Any]:
    return {
        "store": "keychain",
        "credentials": claude_blob(who, generation, **machine),
        "oauth_account": claude_account(who),
    }


@pytest.fixture
def profiles(tmp_path: Path) -> Profiles:
    return Profiles(
        str(tmp_path / "state"), FileStore(str(tmp_path / "secrets")), make_backends(tmp_path)
    )


def test_import_plan_and_apply(profiles: Profiles, tmp_path: Path) -> None:
    legacy = tmp_path / "legacy"
    sources = [
        _legacy(legacy, "claude", "work", _claude_payload("alice", mcpOAuth={"s": {}}), "work"),
        _legacy(legacy, "codex", "main", {"auth": codex_auth("bob")}, "main"),
    ]
    before = [p.read_bytes() for p in sources]

    planned = migrate.plan(str(legacy), profiles)
    assert [c.importable for c in planned] == [True, True]
    assert profiles.all() == []

    imported = migrate.apply(planned, profiles)
    assert [(p.kind, p.label) for p in imported] == [("claude", "work"), ("codex", "main")]
    saved = json.loads(profiles.secret(imported[0])[0].reveal())
    assert "mcpOAuth" not in saved["credentials"]
    assert [p.read_bytes() for p in sources] == before  # never touched
    assert migrate.leftovers(str(legacy)) == [str(legacy / "profiles")]


def test_a_finished_renewal_left_behind_is_preferred(profiles: Profiles, tmp_path: Path) -> None:
    legacy = tmp_path / "legacy"
    _legacy(legacy, "claude", "work", _claude_payload("alice", 1), "work")
    rotated = legacy / "rotated"
    rotated.mkdir()
    (rotated / "claude-work.json").write_text(json.dumps(_claude_payload("alice", 2)))

    (candidate,) = migrate.plan(str(legacy), profiles)
    assert candidate.snapshot is not None
    newer = json.loads(candidate.snapshot.secret.reveal())
    assert newer["credentials"]["claudeAiOauth"]["refreshToken"].endswith("refresh-2")


def test_unusable_logins_are_skipped_with_a_reason(profiles: Profiles, tmp_path: Path) -> None:
    legacy = tmp_path / "legacy"
    expired = _claude_payload("bob")
    expired["credentials"]["claudeAiOauth"]["refreshTokenExpiresAt"] = int(time.time() * 1000)
    _legacy(legacy, "claude", "a", expired, "expired")
    _legacy(legacy, "claude", "b", _claude_payload("carol", newKey="x"), "unknown")
    _legacy(legacy, "claude", "c", {"credentials": claude_blob("dave")}, "anonymous")

    problems = {c.label: c.problem for c in migrate.plan(str(legacy), profiles)}
    assert "expired" in (problems["expired"] or "")
    assert "newKey" in (problems["unknown"] or "")
    assert "identity" in (problems["anonymous"] or "")


def test_duplicates_are_skipped_and_name_clashes_renamed(
    profiles: Profiles, tmp_path: Path
) -> None:
    first = tmp_path / "first"
    _legacy(first, "claude", "work", _claude_payload("alice"), "work")
    migrate.apply(migrate.plan(str(first), profiles), profiles)

    second = tmp_path / "second"
    _legacy(second, "claude", "same", _claude_payload("alice"), "anything")
    _legacy(second, "claude", "work", _claude_payload("bob"), "work")
    planned = migrate.plan(str(second), profiles)
    assert planned[0].problem == "skipped: already saved as work"
    imported = migrate.apply(planned, profiles)
    assert [p.label for p in imported] == ["work (imported)"]


def test_cli_dry_run_imports_nothing(
    profiles: Profiles,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    legacy = tmp_path / "legacy"
    _legacy(legacy, "claude", "work", _claude_payload("alice"), "work")

    class FakeApp:
        def __init__(self) -> None:
            self.profiles = profiles

    monkeypatch.setattr(cli.App, "load", classmethod(lambda _cls, _path=None: FakeApp()))
    assert cli.main(["import-legacy", "--from", str(legacy)]) == 0
    assert "run again with --apply" in capsys.readouterr().out
    assert profiles.all() == []
    assert cli.main(["import-legacy", "--from", str(legacy), "--apply"]) == 0
    output = capsys.readouterr().out
    assert "imported 1 of 1" in output
    assert str(legacy / "profiles") in output
    assert "sk-ant" not in output
