from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from auth_picker.app import App
from auth_picker.config import Config
from auth_picker.ui.picker import Picker, Row, draw
from tests.fakes import codex_auth
from tests.test_switch import World


class Answers:
    """Stands in for the user at the prompts."""

    def __init__(self, name: str | None = None, yes: bool = False) -> None:
        self.name, self.yes = name, yes
        self.asked: list[str] = []

    def ask(self, question: str, _initial: str) -> str | None:
        self.asked.append(question)
        return self.name

    def confirm(self, question: str) -> bool:
        self.asked.append(question)
        return self.yes


def _picker(world: World, answers: Answers) -> Picker:
    app = App(
        Config(),
        world.profiles.store,
        world.profiles.backends,
        world.profiles,
        world.journals,
        world.switcher,
    )
    return Picker(app, answers.ask, answers.confirm)


@pytest.fixture
def world(tmp_path: Path) -> World:
    w = World(tmp_path)
    w.log_in("alice")
    w.save("A", "alice")
    w.save("B", "bob")
    return w


def _select(picker: Picker, label: str) -> None:
    rows = [r for r in picker.rows() if not r.header]
    picker.cursor = [r.profile.label if r.profile else "" for r in rows].index(label)


def test_rows_show_who_is_live(world: World) -> None:
    rows = _picker(world, Answers()).rows()
    assert rows[0].header
    assert rows[0].text == "Claude Code — live"
    assert [(r.profile.label, r.live) for r in rows[1:] if r.profile] == [("A", True), ("B", False)]


def test_enter_switches(world: World) -> None:
    picker = _picker(world, Answers())
    _select(picker, "B")
    assert picker.handle("enter")
    assert world.who() == "bob@example.com"
    assert picker.message == "switched to B"
    assert not picker.handle("q")


def test_save_asks_for_a_name(world: World) -> None:
    world.log_in("carol")
    answers = Answers(name="Spare")
    picker = _picker(world, answers)
    assert "not saved, press s" in picker.rows()[0].text
    picker.handle("s")
    assert picker.message == "saved as Spare"
    assert world.profiles.find("claude", "Spare")


def test_delete_needs_a_yes_and_says_when_it_is_the_only_copy(world: World) -> None:
    answers = Answers(yes=False)
    picker = _picker(world, answers)
    _select(picker, "B")
    picker.handle("x")
    assert "ONLY copy" in answers.asked[-1]
    assert len(world.profiles.all()) == 2
    answers.yes = True
    picker.handle("x")
    assert [p.label for p in world.profiles.all()] == ["A"]


def test_errors_become_messages(world: World) -> None:
    picker = _picker(world, Answers())
    picker.handle("u")  # nothing to undo yet
    assert picker.message == "nothing to undo for claude"


def test_a_risky_codex_switch_asks_first(tmp_path: Path) -> None:
    w = World(tmp_path, running=1)
    codex = w.profiles.backends["codex"]
    (w.home / ".codex" / "auth.json").write_text(json.dumps(codex_auth("alice", expires_in=60)))
    live = codex.read_live()
    assert live is not None
    w.profiles.create("A", live)
    w.profiles.create(
        "B",
        codex.parse_secret(
            type(live.secret)(
                json.dumps({"schema": 1, "kind": "codex", "auth": codex_auth("bob")}).encode()
            )
        ),
    )
    answers = Answers(yes=False)
    picker = _picker(w, answers)
    _select(picker, "B")
    picker.handle("enter")
    assert picker.message == "not switched"
    answers.yes = True
    picker.handle("enter")
    assert picker.message == "switched to B"


class TinyScreen:
    """A window that, like curses, refuses writes outside itself."""

    def __init__(self, height: int, width: int) -> None:
        self.size = (height, width)
        self.lines: dict[int, str] = {}

    def getmaxyx(self) -> tuple[int, int]:
        return self.size

    def erase(self) -> None:
        self.lines.clear()

    def addnstr(self, y: int, x: int, text: str, n: int, attr: int = 0) -> None:
        del attr
        height, width = self.size
        if not (0 <= y < height and 0 <= x < width) or x + min(len(text), n) > width:
            raise ValueError("outside the window")
        self.lines[y] = text[:n]

    def refresh(self) -> None:
        pass


@pytest.mark.parametrize("size", [(1, 1), (2, 5), (4, 20), (40, 200)])
def test_drawing_fits_any_window(world: World, size: tuple[int, int]) -> None:
    picker = _picker(world, Answers())
    picker.message = "x" * 500
    rows = [*picker.rows(), Row("claude", "y" * 500)]
    screen = TinyScreen(*size)
    draw(screen, picker, rows, {})
    assert all(len(line) < size[1] for line in screen.lines.values())


@pytest.mark.parametrize("yes", [True, False])
def test_the_picker_asks_before_restarting_codex(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, yes: bool
) -> None:
    from auth_picker import procscan  # noqa: PLC0415
    from tests.test_switch import _codex_world  # noqa: PLC0415

    w = _codex_world(tmp_path, running=0)
    w.switcher.scan = lambda _kind: procscan.Sessions(running=1, servers=1)
    calls: list[str] = []
    monkeypatch.setattr(w.profiles.backends["codex"], "restart_server", lambda: calls.append("x"))
    asked: list[str] = []

    def confirm(question: str) -> bool:
        asked.append(question)
        return yes if question.startswith("Restart Codex") else True  # yes to the renewal guard

    app = _picker(w, Answers()).app
    picker = Picker(app, Answers().ask, confirm)
    _select(picker, "B")
    picker.handle("enter")
    assert asked[-1].startswith("Restart Codex's background server")
    assert bool(calls) is yes


def test_a_slow_usage_read_never_holds_up_the_picker(world: World) -> None:
    import threading  # noqa: PLC0415

    from auth_picker.usage import Reading, Usage  # noqa: PLC0415

    release = threading.Event()

    class SlowUsage(Usage):
        def refresh(self, snapshot: object) -> Reading:
            del snapshot
            release.wait(5)
            return Reading()

    picker = _picker(world, Answers())
    picker.app.usage = SlowUsage(str(world.root / "state"), 300)
    started = time.monotonic()
    picker.refresh_usage_soon()
    picker.rows()
    assert time.monotonic() - started < 0.5
    assert picker.busy
    release.set()
    picker.finish()
    assert not picker.busy


def test_switching_shows_progress_first(world: World) -> None:
    shown: list[str] = []
    answers = Answers()
    picker = Picker(_picker(world, answers).app, answers.ask, answers.confirm, shown.append)
    _select(picker, "B")
    picker.handle("enter")
    assert shown == ["switching to B…"]
    assert picker.message.startswith("switched to B")


def test_d_shows_every_usage_window_under_each_profile(world: World) -> None:
    from auth_picker.usage import Reading, Usage, Window  # noqa: PLC0415

    picker = _picker(world, Answers())
    picker.app.usage = Usage(str(world.root / "state"), 300)
    a = world.profiles.find("claude", "A")
    reading = Reading(
        read_at=time.time(), windows=[Window("session", 12, None), Window("weekly", 37, None)]
    )
    picker.app.usage.cached = lambda: {a.fingerprint: reading}  # type: ignore[method-assign]
    assert not any(r.detail for r in picker.rows())
    picker.handle("d")
    rows = picker.rows()
    assert [r.text.split()[1] for r in rows if r.detail][:2] == ["weekly", "session"]
    _select(picker, "B")  # details are never selectable
    assert picker.selected(picker.rows()).profile.label == "B"  # type: ignore[union-attr]
