"""Moving one Claude session to another account (design §14).

The session is stopped and started again in the same pane with
``claude --resume <id>``, in the target account's slot or on the main store.
Its conversation is Claude's, on disk, and is not touched.
"""

from __future__ import annotations

import glob
import json
import os
import re
import shlex
import signal
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from auth_picker import herdr, procscan
from auth_picker.backends.claude import SLOT_VAR
from auth_picker.errors import AuthPickerError
from auth_picker.fsutil import read_private, write_private
from auth_picker.profiles import Profile
from auth_picker.slots import Slots
from auth_picker.switch import NeedsConfirmation

# Kept when the session restarts: they set up the session, they don't pick
# one. Each maps to how many values follow it: 0, 1, or "many" (until the next
# flag, as Claude's own parser reads them).
KEEP: dict[str, int | str] = {
    "--dangerously-skip-permissions": 0,
    "--allow-dangerously-skip-permissions": 0,
    "--verbose": 0,
    "--ide": 0,
    "--chrome": 0,
    "--no-chrome": 0,
    "--strict-mcp-config": 0,
    "--disable-slash-commands": 0,
    "--bare": 0,
    "--safe-mode": 0,
    "--brief": 0,
    "--ax-screen-reader": 0,
    "--model": 1,
    "--permission-mode": 1,
    "--effort": 1,
    "--fallback-model": 1,
    "--agent": 1,
    "--agents": 1,
    "--settings": 1,
    "--setting-sources": 1,
    "--plugin-dir": 1,
    "--append-system-prompt": 1,
    "--system-prompt": 1,
    "--autocompact": 1,
    "--add-dir": "many",
    "--mcp-config": "many",
    "--allowedTools": "many",
    "--allowed-tools": "many",
    "--disallowedTools": "many",
    "--disallowed-tools": "many",
    "--tools": "many",
    "--betas": "many",
}
# Replaced by our own --resume <id>: they choose which session runs.
REPLACED: dict[str, int | str] = {
    "-c": 0,
    "--continue": 0,
    "--fork-session": 0,
    "-r": "optional",
    "--resume": "optional",
    "--session-id": 1,
    "-n": 1,
    "--name": 1,
}
# A session started like this can't be restarted in place.
REFUSED = {
    "-p": "it runs non-interactively (-p)",
    "--print": "it runs non-interactively (--print)",
    "--bg": "it runs in the background (--bg)",
    "--background": "it runs in the background (--background)",
    "-w": "it runs in its own worktree (-w)",
    "--worktree": "it runs in its own worktree (--worktree)",
    "--tmux": "it runs in tmux (--tmux)",
    "--remote-control": "it is under remote control",
    "--cloud": "it is a cloud session",
    "--teleport": "it is a teleported session",
    "--desktop": "it runs in Claude Desktop",
    "--from-pr": "it was opened from a pull request",
}
# Statuses herdr reports for an agent that is not in the middle of a reply.
AT_REST = ("idle", "done")
EXIT_TIMEOUT_S = 10.0
SHELL_TIMEOUT_S = 5.0
START_TIMEOUT_S = 20.0
# A restarted Claude must still run this long after it appears: one that
# can't start (say, a conversation it can't find) exits within a second.
SETTLE_S = 2.0
MAX_TRANSCRIPT_SCAN = 64 * 1024 * 1024
POLL_S = 0.2
PANES_FILE = "panes.json"
# How the picker learns which pane it was opened from.
PANE_VAR = "AUTH_PICKER_PANE"
_UNQUOTABLE = re.compile(r"[\x00-\x1f\x7f\\]")


class SessionError(AuthPickerError):
    pass


@dataclass(frozen=True)
class PaneSession:
    pane_id: str
    pid: int
    argv: list[str]
    shell_pid: int
    session_id: str
    status: str
    profile_id: str | None  # its slot's profile; None: the main store
    # It has a saved conversation to resume. A session nobody has written to
    # yet has none, and `--resume` would make Claude exit at once.
    resumable: bool = True


@dataclass
class Moved:
    status: str  # "moved" | "already"
    target: str
    notes: list[str] = field(default_factory=list)


def _values(rest: list[str], i: int, count: int | str) -> int:
    """Index after the values that follow a flag taking ``count`` of them."""
    if count == 0:
        return i
    if count == 1:
        return min(i + 1, len(rest))
    while i < len(rest) and not rest[i].startswith("-"):
        i += 1
        if count == "optional":
            break
    return i


def has_conversation(config_dir: str, session_id: str) -> bool:
    """Claude saved at least one message of this session (``--resume`` can find it)."""
    pattern = os.path.join(glob.escape(config_dir), "projects", "*", f"{session_id}.jsonl")
    for path in glob.glob(pattern):
        try:
            with open(path, "rb") as handle:
                seen = 0
                for line in handle:
                    seen += len(line)
                    if b'"type":"user"' in line or b'"type":"assistant"' in line:
                        return True
                    if seen > MAX_TRANSCRIPT_SCAN:
                        return True  # that much is a conversation
        except OSError:
            continue
    return False


def restart_argv(argv: list[str], session_id: str | None) -> tuple[list[str], list[str]]:
    """The argv to start this session again, and what was left out (flag names only).

    ``session_id`` None: it has no conversation yet, so it starts fresh.
    """
    if not argv:
        raise SessionError("no-argv", "herdr did not say how this session was started")
    lead = 2 if os.path.basename(argv[0]) in ("node", "bun") and len(argv) > 1 else 1
    kept, dropped = list(argv[:lead]), set()
    rest = argv[lead:]
    i = 0
    while i < len(rest):
        arg = rest[i]
        if arg == "--":
            dropped.update(["a prompt argument"] if rest[i + 1 :] else [])
            break
        if not arg.startswith("-") or arg == "-":
            dropped.add("a prompt argument")
            i += 1
            continue
        name, has_value, _ = arg.partition("=")
        if name in REFUSED:
            raise SessionError(
                "unsupported-session", f"this session can't be moved: {REFUSED[name]}"
            )
        count = KEEP.get(name, REPLACED.get(name, "optional"))
        if name not in KEEP and name not in REPLACED:
            dropped.add(name)
        end = i + 1 if has_value else _values(rest, i + 1, count)
        if name in KEEP:
            kept.extend(rest[i:end])
        i = end
    if any(_UNQUOTABLE.search(arg) for arg in kept):
        raise SessionError(
            "unquotable",
            "this session was started with an argument this can't retype safely "
            "(a control character or backslash); restart it yourself",
        )
    resume = ["--resume", session_id] if session_id else []
    return [*kept, *resume], sorted(dropped)


# Claude under Node renames its process, which hides its environment from
# `ps` on macOS; with this set it doesn't, so the slot it runs in stays visible.
VISIBLE = "CLAUDE_CODE_DISABLE_TERMINAL_TITLE=1"
# How long a slot stays reserved after a restart failed, for the user to run
# the command shown.
HOLD_AFTER_FAILURE_S = 600.0


def command_line(argv: list[str], slot_dir: str | None) -> str:
    """What gets typed. The leading space keeps it out of shell history where set up."""
    env = f"env {SLOT_VAR}={shlex.quote(slot_dir)} {VISIBLE} " if slot_dir else ""
    return " " + env + shlex.join(argv)


def _claude_process(info: dict[str, Any]) -> tuple[int, list[str]] | None:
    for process in info.get("foreground_processes") or []:
        argv = process.get("argv") if isinstance(process, dict) else None
        pid = process.get("pid") if isinstance(process, dict) else None
        if (
            isinstance(argv, list)
            and argv
            and all(isinstance(a, str) for a in argv)
            and isinstance(pid, int)
            and procscan.kind_of(argv[0], " ".join(argv)) == "claude"
        ):
            return pid, argv
    return None


def inspect(slots: Slots, pane_id: str) -> PaneSession:
    """The Claude session in a pane, as far as moving it is concerned."""
    info = herdr.process_info(pane_id)
    if info is None:
        raise SessionError("no-pane", f"herdr knows no pane {pane_id}")
    shell = info.get("shell_pid")
    found = _claude_process(info)
    if found is None or not isinstance(shell, int):
        raise SessionError("no-claude", "no Claude session is running in that pane")
    pid, argv = found
    if procscan.parent_of(pid) != shell:
        raise SessionError(
            "not-from-shell",
            "this Claude session was not started from the pane's shell, so it can't be "
            "restarted in place",
        )
    agent = herdr.agent_of(pane_id) or {}
    session = agent.get("agent_session")
    value = session.get("value") if isinstance(session, dict) else None
    try:
        session_id = str(uuid.UUID(str(value)))
    except ValueError:
        raise SessionError(
            "no-session-id", "herdr does not know this session's id yet; try again in a moment"
        ) from None
    status = str(agent.get("agent_status") or "unknown")
    slot_dir = procscan.slot_of(pid, SLOT_VAR, slots.dirs())
    profile_id = slots.profile_of_dir(slot_dir) if slot_dir else None
    resumable = has_conversation(slots.claude_dir, session_id)
    return PaneSession(pane_id, pid, argv, shell, session_id, status, profile_id, resumable)


def _wait(condition: Callable[[], Any], timeout: float) -> Any:
    deadline = time.monotonic() + timeout
    while True:
        result = condition()
        if result or time.monotonic() >= deadline:
            return result
        time.sleep(POLL_S)


def _restart(
    session: PaneSession,
    command: str,
    slot_dir: str | None,
    progress: Callable[[str], None],
    name: str,
) -> int:
    """Stop the session, type ``command`` at the shell, and wait for it to run."""
    pane_id = session.pane_id
    progress("stopping the session…")
    if procscan.parent_of(session.pid) != session.shell_pid:
        raise SessionError("session-gone", "the session ended on its own; nothing was moved")
    os.kill(session.pid, signal.SIGTERM)
    if not _wait(lambda: not procscan.alive(session.pid), EXIT_TIMEOUT_S):
        raise SessionError("no-exit", "Claude did not exit; nothing else was done")

    def at_prompt() -> bool:
        info = herdr.process_info(pane_id) or {}
        foreground = [p.get("pid") for p in info.get("foreground_processes") or []]
        return foreground == [session.shell_pid]

    if not _wait(at_prompt, SHELL_TIMEOUT_S):
        raise SessionError(
            "no-prompt", f"the pane's shell did not come back; start the session yourself:{command}"
        )
    progress(f"starting it on {name}…")
    herdr.send_keys(pane_id, "ctrl+u")
    herdr.run_in_pane(pane_id, command)

    def started() -> int | None:
        found = _claude_process(herdr.process_info(pane_id) or {})
        if found is None or found[0] == session.pid:
            return None
        return found[0] if not session.resumable or session.session_id in found[1] else None

    pid: int | None = _wait(started, START_TIMEOUT_S)
    if not pid:
        raise SessionError(
            "no-start", f"the session did not start again; start it yourself:{command}"
        )
    if _wait(lambda: not procscan.alive(pid), SETTLE_S):
        raise SessionError(
            "exited",
            f"Claude exited right after starting (see that pane); to try again:{command}",
        )
    if slot_dir is not None and procscan.slot_of(pid, SLOT_VAR, [slot_dir]) != slot_dir:
        raise SessionError(
            "wrong-store", f"the session started without its own account; restart it:{command}"
        )
    return pid


def move(
    slots: Slots,
    pane_id: str,
    target: Profile | None,
    *,
    force: bool = False,
    progress: Callable[[str], None] = lambda _: None,
) -> Moved:
    """Restart the Claude session in ``pane_id`` on ``target`` (None: the main account)."""
    if target is not None and target.kind != "claude":
        raise SessionError("slot-kind", "only Claude sessions can have an account of their own")
    session = inspect(slots, pane_id)
    main = slots.backend.live_identity()
    if target is not None and main is not None and main.fingerprint("claude") == target.fingerprint:
        target = None  # the main account: run it on the main store
    name = target.label if target is not None else "the main account"
    if session.profile_id == (target.id if target is not None else None):
        return Moved("already", name)
    argv, dropped = restart_argv(session.argv, session.session_id if session.resumable else None)
    if session.status not in AT_REST and not force:
        raise NeedsConfirmation(
            "session-working",
            "this session is replying; moving it now cuts the reply off (the conversation "
            "so far is kept)",
        )
    slot_dir = slots.lend(target) if target is not None else None
    try:
        pid = _restart(session, command_line(argv, slot_dir), slot_dir, progress, name)
    except BaseException:
        if target is not None:
            # The session is stopped; keep its slot for the command shown.
            slots.release(target.id, hold_s=HOLD_AFTER_FAILURE_S)
        raise
    if target is not None:
        slots.release(target.id)
    notes = [] if session.resumable else ["it had no conversation yet, so it started fresh"]
    if dropped:
        notes.append("not carried over: " + ", ".join(dropped))
    if target is not None:
        notes.append(
            "MCP servers that need a login will ask again in this session; "
            "Claude's /status still names the main account"
        )
    _remember(slots, {pane_id: (pid, target.id if target is not None else None)})
    if session.profile_id is not None:
        returned = slots.give_back(session.profile_id)
        if returned:
            notes.append(returned)
    return Moved("moved", name, notes)


# -- which account each pane runs on (for the badges) ---------------------------


def _cache_path(slots: Slots) -> str:
    return os.path.join(slots.profiles.state_dir, PANES_FILE)


def _cache(slots: Slots) -> dict[str, tuple[int, str | None]]:
    data = read_private(_cache_path(slots), 256 * 1024)
    try:
        raw = json.loads(data) if data else {}
        return {
            str(pane): (int(entry["pid"]), entry["profile_id"])
            for pane, entry in raw.items()
            if entry.get("profile_id") is None or isinstance(entry.get("profile_id"), str)
        }
    except (ValueError, KeyError, TypeError, AttributeError):
        return {}


def _remember(slots: Slots, entries: dict[str, tuple[int, str | None]]) -> None:
    cache = {pane: e for pane, e in _cache(slots).items() if procscan.alive(e[0])}
    cache.update(entries)
    body = {pane: {"pid": pid, "profile_id": owner} for pane, (pid, owner) in cache.items()}
    write_private(_cache_path(slots), json.dumps(body).encode())


def pane_accounts(
    slots: Slots, panes: list[str], fresh: frozenset[str] = frozenset()
) -> dict[str, str | None]:
    """pane id -> profile id of the slot its Claude runs in (None: the main store).

    With no slots there is nothing to look up. Otherwise a pane is looked up
    (herdr, then its process's environment) when it is in ``fresh``, unknown,
    or its process has gone; the answer is cached by pid.
    """
    try:
        dirs = slots.dirs()
    except AuthPickerError:
        dirs = []
    if not dirs:
        return dict.fromkeys(panes)
    cache = _cache(slots)
    ids = {slots.profile_of_dir(d) for d in dirs}
    found: dict[str, str | None] = {}
    learned: dict[str, tuple[int, str | None]] = {}
    for pane in panes:
        entry = cache.get(pane)
        if (
            pane not in fresh
            and entry is not None
            and procscan.alive(entry[0])
            and (entry[1] is None or entry[1] in ids)
        ):
            found[pane] = entry[1]
            continue
        process = _claude_process(herdr.process_info(pane) or {})
        if process is None:
            found[pane] = None
            continue
        slot_dir = procscan.slot_of(process[0], SLOT_VAR, dirs)
        found[pane] = slots.profile_of_dir(slot_dir) if slot_dir else None
        learned[pane] = (process[0], found[pane])
    if learned:
        _remember(slots, learned)
    return found
