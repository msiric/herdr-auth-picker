"""The commands end to end, against a fake machine (no Keychain, no herdr)."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from auth_picker import badge, cli, procscan
from auth_picker.app import App
from auth_picker.backends.base import Snapshot
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


def test_a_rescue_holding_mixed_up_tokens_cannot_be_adopted(
    world: World, capsys: pytest.CaptureFixture[str]
) -> None:
    world.log_in("alice")
    world.save("A", "alice")
    world.save("B", "bob")
    creds = world.home / ".claude" / ".credentials.json"
    bob = json.loads(world.profiles.store.get(world.profiles.find("claude", "B").key).reveal())  # type: ignore[union-attr]
    blob = json.loads(creds.read_text())
    blob["claudeAiOauth"] = bob["credentials"]["claudeAiOauth"]
    creds.write_text(json.dumps(blob))
    assert run(capsys, "switch", "claude", "B")[0] == 1  # opens a contamination rescue
    rid = world.journals.rescues()[0].rid
    listing = run(capsys, "rescue")[1]
    assert "--adopt" not in listing
    code, text = run(capsys, "rescue", "--adopt", rid)
    assert code == 1
    assert "cannot be saved as a profile" in text
    assert b"refresh-1" in world.profiles.secret(world.profiles.find("claude", "A"))[0].reveal()


def test_the_badge_creates_nothing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HERDR_PLUGIN_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("HERDR_PLUGIN_CONFIG_DIR", str(tmp_path / "config"))
    App.load(readonly=True)
    assert not (tmp_path / "state").exists()


@pytest.mark.parametrize(
    "case",
    [
        ((), "never", False),
        (("--restart-codex",), "never", True),
        ((), "always", True),
        ((), "ask", False),
    ],  # ask, with no terminal to ask on, only tells
)
def test_codex_background_server_restart_policy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    case: tuple[tuple[str, ...], str, bool],
) -> None:
    from tests.test_switch import _codex_world  # noqa: PLC0415

    argv, policy, restarted = case
    w = _codex_world(tmp_path, running=0)
    w.switcher.scan = lambda _kind: procscan.Sessions(running=1, servers=1)
    calls: list[str] = []
    monkeypatch.setattr(w.profiles.backends["codex"], "restart_server", lambda: calls.append("x"))
    app = App(
        Config(codex_restart=policy),
        w.profiles.store,
        w.profiles.backends,
        w.profiles,
        w.journals,
        w.switcher,
    )
    monkeypatch.setattr(App, "load", classmethod(lambda _cls, *_a, **_k: app))
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    code, text = run(capsys, "switch", "codex", "B", "--force", *argv)
    assert code == 0
    assert bool(calls) is restarted
    assert ("restarted Codex's background server" in text) is restarted
    assert ("still uses the previous account" in text) is not restarted


def _event(monkeypatch: pytest.MonkeyPatch, agent: str, status: str | None) -> None:
    data = {"type": "x", "pane_id": "w1:p1", "agent": agent}
    if status is not None:
        data["agent_status"] = status
    monkeypatch.setenv("HERDR_PLUGIN_EVENT_JSON", json.dumps({"event": "x", "data": data}))


def test_events_from_other_agents_load_nothing(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def boom(*_a: object, **_k: object) -> None:
        raise AssertionError("loaded the app for a copilot pane")

    monkeypatch.setattr(App, "load", classmethod(boom))
    _event(monkeypatch, "copilot", "idle")
    assert run(capsys, "event")[0] == 0
    _event(monkeypatch, "claude", "working")  # mid-turn: nothing to do either
    assert run(capsys, "event")[0] == 0


def test_a_finished_turn_reads_usage_and_restamps(
    world: World, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from auth_picker.usage import Reading, Usage  # noqa: PLC0415

    world.log_in("alice")
    world.save("A", "alice")
    app: App = world.app  # type: ignore[attr-defined]
    refreshed: list[str] = []
    stamped: list[object] = []

    class FakeUsage(Usage):
        def refresh(self, snapshot: Snapshot) -> Reading:
            refreshed.append(snapshot.fingerprint)
            return Reading()

    app.usage = FakeUsage(str(world.root / "state"), 300)
    monkeypatch.setattr(badge, "stamp", lambda _app, panes=None: stamped.append(panes))
    _event(monkeypatch, "claude", "idle")
    assert run(capsys, "event")[0] == 0
    assert refreshed == [world.live().fingerprint]
    assert stamped == [None]

    _event(monkeypatch, "claude", None)  # a newly detected pane: badge just that one
    assert run(capsys, "event")[0] == 0
    assert stamped[-1] == {"w1:p1"}


def test_stamp_puts_usage_on_its_own_token(world: World, monkeypatch: pytest.MonkeyPatch) -> None:
    from auth_picker import herdr  # noqa: PLC0415
    from auth_picker.usage import Reading, Usage, Window  # noqa: PLC0415

    world.log_in("alice")
    world.save("Work", "alice")
    app: App = world.app  # type: ignore[attr-defined]
    app.usage = Usage(str(world.root / "state"), 300)
    fingerprint = world.live().fingerprint
    monkeypatch.setattr(
        app.usage,
        "cached",
        lambda: {fingerprint: Reading(read_at=time.time(), windows=[Window("session", 42, None)])},
    )
    monkeypatch.setattr(
        herdr,
        "agents",
        lambda: [{"pane_id": "p1", "agent": "claude"}, {"pane_id": "p2", "agent": "copilot"}],
    )
    calls: list[tuple[object, ...]] = []
    monkeypatch.setattr(herdr, "report", lambda *a: calls.append(a))
    badge.stamp(app)
    assert calls == [("p1", {"acct": "👤 Work", "usage": "42% 5h"}, ())]
