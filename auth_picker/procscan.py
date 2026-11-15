"""Running Claude Code / Codex sessions of this user.

Used for two warnings (design §8, §9): a session that may renew its token in
the middle of a switch, and a Claude session pinned to one account by
CLAUDE_CODE_OAUTH_TOKEN in its environment. Only the presence of that
variable is checked; values are never kept.
"""

from __future__ import annotations

import os
import platform
import re
from collections.abc import Iterator
from dataclasses import dataclass

from auth_picker import proc
from auth_picker.errors import ProcessFailed

PS = "/bin/ps"
PINNING_VAR = "CLAUDE_CODE_OAUTH_TOKEN"
_PINNED = re.compile(rf"(?:^|\s){PINNING_VAR}=\S")


@dataclass(frozen=True)
class Sessions:
    running: int = 0
    pinned: int = 0
    # Codex's background app server, which keeps its login in memory.
    servers: int = 0


def kind_of(argv0: str, args: str) -> str | None:
    name = os.path.basename(argv0)
    npm_install = name in ("node", "bun") and "@anthropic-ai/claude-code" in args
    if name == "claude" or "/claude/versions/" in argv0 or npm_install:
        return "claude"
    if name == "codex":
        return "codex"
    return None


def _macos() -> Iterator[tuple[int, str, str]]:
    listed = proc.run([PS, "-A", "-ww", "-o", "pid=,uid=,args="])
    uid = os.getuid()
    for line in listed.stdout.decode("utf-8", "replace").splitlines():
        try:
            pid, owner, args = line.split(None, 2)
        except ValueError:
            continue
        if pid.isdigit() and owner == str(uid):
            yield int(pid), args.split(" ")[0], args


def _linux() -> Iterator[tuple[int, str, str]]:
    uid = os.getuid()
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            if os.stat(f"/proc/{entry}").st_uid != uid:
                continue
            with open(f"/proc/{entry}/cmdline", "rb") as handle:
                argv = handle.read().split(b"\0")
        except OSError:
            continue
        if argv and argv[0]:
            yield (
                int(entry),
                argv[0].decode("utf-8", "replace"),
                b" ".join(argv).decode("utf-8", "replace"),
            )


def _pinned_macos(pids: list[int]) -> int:
    shown = proc.run([PS, "-E", "-ww", "-o", "pid=,command=", "-p", ",".join(map(str, pids))])
    return sum(
        1 for line in shown.stdout.decode("utf-8", "replace").splitlines() if _PINNED.search(line)
    )


def _pinned_linux(pids: list[int]) -> int:
    marker = b"\0" + PINNING_VAR.encode() + b"="
    count = 0
    for pid in pids:
        try:
            with open(f"/proc/{pid}/environ", "rb") as handle:
                environ = b"\0" + handle.read()
        except OSError:
            continue
        if marker in environ:
            count += 1
    return count


def _environ_macos(pids: list[int]) -> dict[int, str]:
    """``ps -E`` lines: the command, then the environment, space-separated."""
    shown = proc.run([PS, "-E", "-ww", "-o", "pid=,command=", "-p", ",".join(map(str, pids))])
    lines: dict[int, str] = {}
    for line in shown.stdout.decode("utf-8", "replace").splitlines():
        pid, _, rest = line.strip().partition(" ")
        if pid.isdigit():
            lines[int(pid)] = " " + rest + " "
    return lines


def _uses_macos(line: str, assignment: str) -> bool:
    return f" {assignment} " in line


def _environment_shown(line: str) -> bool:
    """False when ``ps -E`` shows no environment for a process.

    A Node-run Claude renames its process (``process.title``), which on macOS
    overwrites the memory ``ps`` reads its arguments and environment from.
    Such a process could be in any slot, so callers must not assume it isn't.
    """
    return " PATH=" in line or " HOME=" in line


def _environ_linux(pid: int) -> bytes | None:
    try:
        with open(f"/proc/{pid}/environ", "rb") as handle:
            return b"\0" + handle.read() + b"\0"
    except OSError:
        return None


def slot_users(var: str, dirs: list[str]) -> dict[str, list[int]]:
    """Running Claude processes with ``var`` set to each of ``dirs`` (design §14).

    Only exact ``var=<dir>`` assignments are looked for; nothing else in any
    environment is kept. A process whose environment can't be seen counts for
    every dir (fail closed). Raises ProcessFailed/OSError if it cannot tell.
    """
    found: dict[str, list[int]] = {d: [] for d in dirs}
    if not dirs:
        return found
    mac = platform.system() == "Darwin"
    pids = [
        pid
        for pid, argv0, args in (_macos() if mac else _linux())
        if kind_of(argv0, args) == "claude" and pid != os.getpid()
    ]
    if not pids:
        return found
    if mac:
        lines = _environ_macos(pids)
        for pid, line in lines.items():
            for d in dirs:
                if _uses_macos(line, f"{var}={d}") or not _environment_shown(line):
                    found[d].append(pid)
    else:
        for pid in pids:
            environ = _environ_linux(pid)
            for d in dirs:
                if environ is not None and f"\0{var}={d}\0".encode() in environ:
                    found[d].append(pid)
    return found


def slot_of(pid: int, var: str, dirs: list[str]) -> str | None:
    """Which of ``dirs`` one process has ``var`` set to, if any. Fails soft."""
    if not dirs:
        return None
    try:
        if platform.system() == "Darwin":
            line = _environ_macos([pid]).get(pid, "")
            return next((d for d in dirs if _uses_macos(line, f"{var}={d}")), None)
        environ = _environ_linux(pid) or b""
        return next((d for d in dirs if f"\0{var}={d}\0".encode() in environ), None)
    except (OSError, ProcessFailed):
        return None


def parent_of(pid: int) -> int | None:
    try:
        if platform.system() == "Darwin":
            shown = proc.run([PS, "-o", "ppid=", "-p", str(pid)])
            value = shown.stdout.decode().strip()
        else:
            with open(f"/proc/{pid}/stat", encoding="utf-8", errors="replace") as handle:
                value = handle.read().rsplit(")", 1)[1].split()[1]
    except (OSError, ProcessFailed, IndexError):
        return None
    return int(value) if value.isdigit() else None


def alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def sessions(kind: str) -> Sessions:
    """Count this user's running sessions of ``kind``. Fails soft: unknown is zero."""
    mac = platform.system() == "Darwin"
    try:
        found = [
            (pid, args)
            for pid, argv0, args in (_macos() if mac else _linux())
            if kind_of(argv0, args) == kind and pid != os.getpid()
        ]
        pids = [pid for pid, _ in found]
        servers = sum(1 for _, args in found if kind == "codex" and " app-server" in args)
        pinned = 0
        if kind == "claude" and pids:
            pinned = _pinned_macos(pids) if mac else _pinned_linux(pids)
    except (OSError, ProcessFailed):
        return Sessions()
    return Sessions(running=len(pids), pinned=pinned, servers=servers)
