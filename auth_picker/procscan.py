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


def kind_of(argv0: str, args: str) -> str | None:
    name = os.path.basename(argv0)
    if name == "claude" or "/claude/versions/" in argv0 or "@anthropic-ai/claude-code" in args:
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


def sessions(kind: str) -> Sessions:
    """Count this user's running sessions of ``kind``. Fails soft: unknown is zero."""
    mac = platform.system() == "Darwin"
    try:
        pids = [
            pid
            for pid, argv0, args in (_macos() if mac else _linux())
            if kind_of(argv0, args) == kind and pid != os.getpid()
        ]
        pinned = 0
        if kind == "claude" and pids:
            pinned = _pinned_macos(pids) if mac else _pinned_linux(pids)
    except (OSError, ProcessFailed):
        return Sessions()
    return Sessions(running=len(pids), pinned=pinned)
