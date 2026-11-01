"""The commands end to end, against a fake machine (no Keychain, no herdr)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from auth_picker import badge, cli
from auth_picker.app import App
from auth_picker.backends.claude import ClaudeBackend
from auth_picker.config import Config
from tests.test_switch import World

Run = tuple[int, str]


@pytest.fixture
def world(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> World:
    w = World(tmp_path)
    app = App(Config(), w.profiles.store, w.profiles.backends, w.profiles, w.journals, w.switcher)
    monkeypatch.setattr(App, "load", classmethod(lambda _cls, *_a, **_k: app))
    monkeypatch.delenv("HERDR_PLUGIN_CONTEXT_JSON", raising=False)
    w.app = app  # type: ignore[attr-defined]
    return w


def run(capsys: pytest.CaptureFixture[str], *argv: str) -> Run:
    code = cli.main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out + captured.err


def test_save_switch_undo_status(world: World, capsys: pytest.CaptureFixture[str]) -> None:
    world.log_in("bob")
    assert run(capsys, "save", "claude", "--name", "B")[0] == 0
    world.log_in("alice")
    assert run(capsys, "save", "claude", "--name", "A")[0] == 0

    code, text = run(capsys, "switch", "claude", "B")
    assert code == 0
    assert "claude: switched to B" in text
    assert world.who() == "bob@example.com"

    code, text = run(capsys, "status")
    assert code == 0
    assert "Claude Code: B (bob@example.com" in text
    assert "● B" in text
    assert "undo available" in text
    assert "sk-ant" not in text

    assert run(capsys, "undo", "claude")[0] == 0
    assert world.who() == "alice@example.com"


def test_next_uses_the_only_kind_with_profiles(
    world: World, capsys: pytest.CaptureFixture[str]
) -> None:
    world.log_in("alice")
    world.save("A", "alice")
    world.save("B", "bob")
    assert run(capsys, "next")[0] == 0
    assert world.who() == "bob@example.com"


def test_delete_is_a_dry_run_without_yes(world: World, capsys: pytest.CaptureFixture[str]) -> None:
    world.log_in("alice")
    world.save("A", "alice")
    world.save("B", "bob")
    code, text = run(capsys, "delete", "claude", "B")
    assert code == 1
    assert "only copy" in text
    assert run(capsys, "delete", "claude", "B", "--yes")[0] == 0
    assert [p.label for p in world.profiles.all()] == ["A"]


def test_badge_never_reads_the_keychain(world: World, monkeypatch: pytest.MonkeyPatch) -> None:
    world.log_in("alice")
    world.save("Work", "alice")

    def no_secrets(*_args: object) -> None:
        raise AssertionError("the badge read the credential store")

    monkeypatch.setattr(ClaudeBackend, "read_live", no_secrets)
    app: App = world.app  # type: ignore[attr-defined]
    assert badge.line(app, ["claude"]) == "👤 Work"
    world.log_in("carol")
    assert badge.line(app, ["claude"]) == "👤 carol*"


def test_badge_format_is_literal(world: World) -> None:
    app: App = world.app  # type: ignore[attr-defined]
    assert badge.render("{glyph}{label} ({kind}) {name.__class__}", "*", "w", "claude") == (
        "*w (Claude) {name.__class__}"
    )
    assert badge.line(app, ["claude"]) == ""  # nothing saved: nothing shown


def test_a_stopped_switch_shows_in_status_and_rescue(
    world: World, capsys: pytest.CaptureFixture[str]
) -> None:
    world.log_in("alice")
    world.save("A", "alice")
    world.save("B", "bob")
    creds = world.home / ".claude" / ".credentials.json"
    blob = json.loads(creds.read_text())
    bob = json.loads(
        (
            world.profiles.store.get(world.profiles.find("claude", "B").key)
            or pytest.fail("no secret")
        ).reveal()
    )
    blob["claudeAiOauth"] = bob["credentials"]["claudeAiOauth"]
    creds.write_text(json.dumps(blob))

    code, text = run(capsys, "switch", "claude", "B")
    assert code == 1
    assert "holds B's tokens" in text
    assert "run `rescue` to review" in run(capsys, "status")[1]
    rid = world.journals.rescues()[0].rid
    assert run(capsys, "rescue", "--clear", rid)[0] == 1
    assert run(capsys, "rescue", "--clear", rid, "--yes")[0] == 0
    assert world.journals.rescues() == []


def test_cleanup_removes_only_unreferenced_secrets(
    world: World, capsys: pytest.CaptureFixture[str]
) -> None:
    world.log_in("alice")
    world.save("A", "alice")
    world.profiles.store.put(
        "profile:00000000-0000-4000-8000-000000000000",
        world.profiles.store.get(world.profiles.find("claude", "A").key)
        or pytest.fail("no secret"),
    )
    code, text = run(capsys, "cleanup")
    assert code == 1
    assert "would delete profile:00000000-0000-4000-8000-000000000000" in text
    assert run(capsys, "cleanup", "--yes")[0] == 0
    assert world.profiles.orphans() == []
    assert world.profiles.secret(world.profiles.find("claude", "A"))


def test_a_second_codex_account_comes_from_a_separate_home(
    world: World, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from tests.fakes import codex_auth  # noqa: PLC0415

    (world.home / ".codex" / "auth.json").write_text(json.dumps(codex_auth("alice")))
    live_before = (world.home / ".codex" / "auth.json").read_bytes()
    other = tmp_path / "second-codex-home"
    other.mkdir()
    (other / "auth.json").write_text(json.dumps(codex_auth("bob")))

    code, text = run(capsys, "save", "codex", "--from", str(other), "--name", "Bob")
    assert code == 0
    assert f"delete {other} now" in text
    assert world.profiles.find("codex", "Bob").identity.email == "bob@example.com"
    assert (world.home / ".codex" / "auth.json").read_bytes() == live_before

    live_home = str(world.home / ".codex")
    assert run(capsys, "save", "codex", "--from", live_home)[0] == 1
    assert run(capsys, "save", "claude", "--from", str(other))[0] == 1


def test_a_kept_login_can_be_adopted_from_a_rescue(
    world: World, capsys: pytest.CaptureFixture[str]
) -> None:
    from tests.test_switch import _crashed_switch  # noqa: PLC0415

    world.log_in("alice")
    world.save("A", "alice")
    world.save("B", "bob")
    _crashed_switch(world)
    world.log_in("carol")  # an outside writer: recovery keeps both and stops
    assert world.switcher.recover("claude") == "rescued"
    rid = world.journals.rescues()[0].rid
    assert "--adopt" in run(capsys, "rescue")[1]
    assert run(capsys, "rescue", "--adopt", rid, "--item", "1")[0] == 0
    assert world.profiles.find("claude", "rescued carol@example.com")
