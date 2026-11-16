"""Moving one Claude session to another account (docs/design.md §14)."""

from __future__ import annotations

import os
import platform
import shlex
import signal
from pathlib import Path
from typing import Any

import pytest

from auth_picker import herdr, procscan, sessions
from auth_picker.backends.claude import SLOT_VAR
from auth_picker.sessions import SessionError, command_line, restart_argv
from auth_picker.slots import Slots
from auth_picker.switch import NeedsConfirmation
from tests.test_slots import Clock, file_slot
from tests.test_switch import World

SID = "4295cc97-74a7-4141-9ece-5eb827a88e83"
SHELL = 100


@pytest.mark.parametrize(
    ("argv", "kept", "dropped"),
    [
        (["claude"], ["claude"], []),
        (
            ["claude", "--model", "opus", "--dangerously-skip-permissions", "-c"],
            ["claude", "--model", "opus", "--dangerously-skip-permissions"],
            [],
        ),
        (["claude", "-r", "old-id", "--effort=high"], ["claude", "--effort=high"], []),
        (["claude", "--teleport", "--model", "x"], ["claude", "--model", "x"], []),
        (
            ["claude", "--add-dir", "a", "b", "--verbose"],
            ["claude", "--add-dir", "a", "b", "--verbose"],
            [],
        ),
        (["claude", "fix the bug"], ["claude"], ["a prompt argument"]),
        (["claude", "--debug", "api", "--model", "x"], ["claude", "--model", "x"], ["--debug"]),
        (["node", "/x/cli.js", "--session-id", "s", "--"], ["node", "/x/cli.js"], []),
    ],
)
def test_a_restart_keeps_only_setup_flags(
    argv: list[str], kept: list[str], dropped: list[str]
) -> None:
    assert restart_argv(argv, SID) == ([*kept, "--resume", SID], dropped)


@pytest.mark.parametrize("flag", ["-p", "--print", "--bg", "-w", "--tmux", "--cloud"])
def test_sessions_that_cannot_restart_in_place_are_refused(flag: str) -> None:
    with pytest.raises(SessionError, match="can't be moved"):
        restart_argv(["claude", flag], SID)


def test_an_argument_that_cannot_be_retyped_safely_is_refused() -> None:
    with pytest.raises(SessionError, match="retype"):
        restart_argv(["claude", "--append-system-prompt", "a\\nb"], SID)


def test_the_typed_command_quotes_everything() -> None:
    line = command_line(["claude", "--append-system-prompt", "it's $HOME"], "/s p/slot")
    assert line.startswith(f" env {SLOT_VAR}='/s p/slot' {sessions.VISIBLE} claude ")
    assert shlex.split(line) == [
        "env",
        f"{SLOT_VAR}=/s p/slot",
        sessions.VISIBLE,
        "claude",
        "--append-system-prompt",
        "it's $HOME",
    ]


class FakePane:
    """A herdr pane running a shell, with Claude in the foreground."""

    def __init__(self, argv: list[str], status: str = "idle", env: str | None = None) -> None:
        self.claude: tuple[int, list[str], str | None] | None = (200, argv, env)
        self.status = status
        self.typed: list[str] = []
        self.keys: list[str] = []
        self.killed: list[int] = []

    def info(self, _pane: str) -> dict[str, Any]:
        fg = [{"pid": SHELL, "argv": ["-zsh"]}]
        if self.claude:
            fg = [{"pid": self.claude[0], "argv": self.claude[1]}]
        return {"shell_pid": SHELL, "foreground_processes": fg}

    def agent(self, pane: str) -> dict[str, Any]:
        session = {"agent": "claude", "kind": "id", "value": SID}
        return {"pane_id": pane, "agent_status": self.status, "agent_session": session}

    def kill(self, pid: int, sig: int) -> None:
        assert sig == signal.SIGTERM
        self.killed.append(pid)
        self.claude = None

    def run(self, _pane: str, command: str) -> bool:
        self.typed.append(command)
        words = shlex.split(command)
        env = None
        if words[0] == "env":
            env = words[1].split("=", 1)[1]
            words = words[1:]
            while "=" in words[0]:
                words = words[1:]
        self.claude = (300, words, env)
        return True

    def slot_of(self, pid: int, _var: str, dirs: list[str]) -> str | None:
        if self.claude and self.claude[0] == pid and self.claude[2] in dirs:
            return self.claude[2]
        return None


@pytest.fixture
def world(tmp_path: Path) -> World:
    w = World(tmp_path)
    w.log_in("alice")
    w.save("A", "alice")
    w.save("B", "bob")
    return w


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def slots(world: World, clock: Clock) -> Slots:
    made = Slots(
        world.switcher, users=lambda dirs: {d: [] for d in dirs}, clock=clock, make_slot=file_slot
    )
    world.switcher.slots = made
    return made


def install(monkeypatch: pytest.MonkeyPatch, pane: FakePane, parent: int = SHELL) -> None:
    monkeypatch.setattr(herdr, "process_info", pane.info)
    monkeypatch.setattr(herdr, "agent_of", pane.agent)
    monkeypatch.setattr(herdr, "run_in_pane", pane.run)

    def send_keys(_pane: str, *keys: str) -> bool:
        pane.keys.extend(keys)
        return True

    monkeypatch.setattr(herdr, "send_keys", send_keys)
    monkeypatch.setattr(os, "kill", pane.kill)
    monkeypatch.setattr(procscan, "parent_of", lambda _pid: parent)
    monkeypatch.setattr(procscan, "alive", lambda pid: bool(pane.claude and pane.claude[0] == pid))
    monkeypatch.setattr(procscan, "slot_of", pane.slot_of)
    monkeypatch.setattr(sessions, "POLL_S", 0.0)
    monkeypatch.setattr(sessions, "SETTLE_S", 0.0)


def converse(world: World, *lines: str) -> None:
    """Claude's saved transcript for SID."""
    folder = world.home / ".claude" / "projects" / "-work"
    folder.mkdir(parents=True, exist_ok=True)
    body = lines or ('{"type":"user","message":{"content":"hi"}}',)
    (folder / f"{SID}.jsonl").write_text("\n".join(body) + "\n")


def test_a_session_moves_to_its_own_account_and_keeps_its_conversation(
    world: World, slots: Slots, monkeypatch: pytest.MonkeyPatch
) -> None:
    pane = FakePane(["claude", "--model", "opus", "fix it"])
    install(monkeypatch, pane)
    converse(world)
    b = world.profiles.find("claude", "B")
    moved = sessions.move(slots, "w1:p2", b)
    assert moved.status == "moved"
    assert pane.killed == [200]
    assert pane.keys == ["ctrl+u"]
    directory = slots.directory(b.id)
    org = f"{sessions.ORG_VAR}=org-1-bob"  # B's own organization, not the main account's
    assert pane.typed == [
        f" env {SLOT_VAR}={directory} {sessions.VISIBLE} {org} claude --model opus --resume {SID}"
    ]
    assert slots.get(b.id) is not None
    assert any("prompt" in note for note in moved.notes)
    assert world.who() == "alice@example.com"  # the other sessions stay on the main account
    assert sessions.pane_accounts(slots, ["w1:p2"]) == {"w1:p2": b.id}


def test_a_replying_session_is_not_cut_off_without_asking(
    world: World, slots: Slots, monkeypatch: pytest.MonkeyPatch
) -> None:
    pane = FakePane(["claude"], status="working")
    install(monkeypatch, pane)
    with pytest.raises(NeedsConfirmation):
        sessions.move(slots, "w1:p2", world.profiles.find("claude", "B"))
    assert pane.killed == []
    assert slots.all() == []


def test_moving_back_to_the_main_account_returns_the_slot(
    world: World, slots: Slots, monkeypatch: pytest.MonkeyPatch
) -> None:
    b = world.profiles.find("claude", "B")
    directory = slots.lend(b)
    slots.release(b.id)
    pane = FakePane(["claude", "--resume", SID], env=directory)
    install(monkeypatch, pane)
    converse(world)
    moved = sessions.move(slots, "w1:p2", None)
    assert pane.typed == [f" claude --resume {SID}"]
    assert moved.target == "the main account"
    assert slots.all() == []


def test_choosing_the_main_accounts_profile_runs_it_on_the_main_store(
    world: World, slots: Slots, monkeypatch: pytest.MonkeyPatch
) -> None:
    install(monkeypatch, FakePane(["claude"]))
    moved = sessions.move(slots, "w1:p2", world.profiles.find("claude", "A"))
    assert moved.status == "already"
    assert slots.all() == []


def test_a_session_not_started_from_the_panes_shell_is_left_alone(
    world: World, slots: Slots, monkeypatch: pytest.MonkeyPatch
) -> None:
    pane = FakePane(["claude"])
    install(monkeypatch, pane, parent=999)
    with pytest.raises(SessionError, match="shell"):
        sessions.move(slots, "w1:p2", world.profiles.find("claude", "B"))
    assert pane.killed == []


def test_without_slots_no_pane_is_looked_up(slots: Slots, monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(_pane: str) -> None:
        raise AssertionError("looked up a pane")

    monkeypatch.setattr(herdr, "process_info", fail)
    assert sessions.pane_accounts(slots, ["w1:p1"]) == {"w1:p1": None}


def test_a_slot_dir_is_matched_whole_in_a_process_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(platform, "system", lambda: "Darwin")
    monkeypatch.setattr(
        procscan, "_macos", lambda: iter([(7, "claude", "claude"), (8, "claude", "claude")])
    )
    monkeypatch.setattr(
        procscan,
        "_environ_macos",
        lambda _pids: {
            7: f" claude HOME=/h {SLOT_VAR}=/s/abcd TERM=x ",
            8: f" claude HOME=/h {SLOT_VAR}=/s/abc ",
        },
    )
    assert procscan.slot_users(SLOT_VAR, ["/s/abc"]) == {"/s/abc": [8]}


def test_a_failed_restart_keeps_the_slot_for_the_command_shown(
    world: World, slots: Slots, clock: Clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    pane = FakePane(["claude"])
    install(monkeypatch, pane)
    monkeypatch.setattr(herdr, "run_in_pane", lambda _p, _c: True)  # nothing starts
    monkeypatch.setattr(sessions, "START_TIMEOUT_S", 0.0)
    b = world.profiles.find("claude", "B")
    with pytest.raises(SessionError, match="start it yourself"):
        sessions.move(slots, "w1:p2", b)
    assert slots.tidy() == []  # still held
    clock.now += sessions.HOLD_AFTER_FAILURE_S + 1
    assert len(slots.tidy()) == 1


def test_a_claude_whose_environment_is_hidden_counts_as_using_every_slot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(platform, "system", lambda: "Darwin")
    monkeypatch.setattr(procscan, "_macos", lambda: iter([(9, "claude", "claude")]))
    monkeypatch.setattr(procscan, "_environ_macos", lambda _pids: {9: " claude "})
    assert procscan.slot_users(SLOT_VAR, ["/s/a", "/s/b"]) == {"/s/a": [9], "/s/b": [9]}


def test_a_session_with_nothing_said_yet_starts_fresh_on_the_account(
    world: World, slots: Slots, monkeypatch: pytest.MonkeyPatch
) -> None:
    pane = FakePane(["claude", "--model", "opus"])
    install(monkeypatch, pane)
    converse(world, '{"type":"file-history-snapshot"}')  # written before any message
    b = world.profiles.find("claude", "B")
    moved = sessions.move(slots, "w1:p2", b)
    directory = slots.directory(b.id)
    org = f"{sessions.ORG_VAR}=org-1-bob"
    assert pane.typed == [
        f" env {SLOT_VAR}={directory} {sessions.VISIBLE} {org} claude --model opus"
    ]
    assert "started fresh" in moved.notes[0]


def test_a_claude_that_exits_right_after_starting_is_a_failed_move(
    world: World, slots: Slots, monkeypatch: pytest.MonkeyPatch
) -> None:
    pane = FakePane(["claude"])
    install(monkeypatch, pane)
    converse(world)
    monkeypatch.setattr(procscan, "alive", lambda pid: pid == 200 and pane.claude is not None)
    b = world.profiles.find("claude", "B")
    with pytest.raises(SessionError, match="exited right after starting"):
        sessions.move(slots, "w1:p2", b)
    assert slots.tidy() == []  # its slot is held for a retry
