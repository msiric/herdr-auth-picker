"""The overlay picker: pick an account, save, rename, delete, undo.

``Picker`` holds the state and handles keys, with no curses in it, so it is
tested directly. ``run`` draws it with curses. Repaints use each backend's
``live_identity``, which reads no secrets: only an actual switch or save
touches the credential store.
"""

from __future__ import annotations

import contextlib
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

from auth_picker import herdr, usage
from auth_picker.app import App
from auth_picker.backends import KINDS
from auth_picker.backends.base import Unsupported
from auth_picker.errors import AuthPickerError
from auth_picker.profiles import Profile
from auth_picker.switch import NeedsConfirmation, Outcome

TITLES = {"claude": "Claude Code", "codex": "Codex"}
HELP = "j/k move · enter switch · s save · r rename · x delete · u undo · q quit"
REFRESH_MS = 3000
POLL_BUSY_MS = 200

Ask = Callable[[str, str], "str | None"]
Confirm = Callable[[str], bool]


@dataclass(frozen=True)
class Row:
    kind: str
    text: str
    profile: Profile | None = None
    live: bool = False

    @property
    def header(self) -> bool:
        return self.profile is None


class Picker:
    def __init__(
        self,
        app: App,
        ask: Ask,
        confirm: Confirm,
        progress: Callable[[str], None] | None = None,
    ) -> None:
        self.app = app
        self.ask = ask
        self.confirm = confirm
        # Shows a line at once, before slow work (a switch) starts.
        self.progress = progress or (lambda _text: None)
        self.cursor = 0
        self.message = ""
        self.usage_read_at = 0.0
        self._lock = threading.Lock()
        self._workers: list[threading.Thread] = []
        self._writers: list[threading.Thread] = []

    # -- background work ---------------------------------------------------
    #
    # Anything slow that the screen does not need first (usage reads, the
    # process scan after a switch) runs on a thread, so keys never wait on it.
    # Only the main thread touches curses.

    @property
    def busy(self) -> bool:
        self._workers = [w for w in self._workers if w.is_alive()]
        return bool(self._workers)

    def _background(self, work: Callable[[], None], *, writes: bool = False) -> None:
        worker = threading.Thread(target=work, daemon=True)
        self._workers.append(worker)
        if writes:
            self._writers.append(worker)
        worker.start()

    def finish(self, timeout: float = 0.3) -> None:
        """On close, wait briefly only for work that is writing a file.

        Work that only shows something (the scan after a switch) is dropped.
        """
        deadline = time.monotonic() + timeout
        for worker in self._writers:
            worker.join(max(0.0, deadline - time.monotonic()))

    def _note(self, text: str) -> None:
        with self._lock:
            self.message = f"{self.message} ({text})" if self.message else text

    def refresh_usage_soon(self) -> None:
        """Start a usage read in the background if one is due and none is running."""
        reader = self.app.usage
        if reader is None or self.busy or time.time() - self.usage_read_at < reader.ttl_s:
            return
        self.usage_read_at = time.time()
        self._background(lambda: self.refresh_usage(force=True), writes=True)

    # -- model -------------------------------------------------------------

    def refresh_usage(self, force: bool = False) -> None:
        """Read the live accounts' usage, at most once per TTL (opt-in)."""
        reader = self.app.usage
        now = time.time()
        if reader is None or (not force and now - self.usage_read_at < reader.ttl_s):
            return
        self.usage_read_at = now
        for kind in KINDS:
            if not self.app.profiles.of_kind(kind):
                continue
            with contextlib.suppress(AuthPickerError):
                live = self.app.backends[kind].read_live()
                if live is not None:
                    reader.refresh(live)

    def _usage_text(self, fingerprint: str) -> str:
        if self.app.usage is None:
            return ""
        reading = self.app.usage.cached().get(fingerprint)
        text = usage.summary(reading, time.time(), self.app.config.usage.ttl_s)
        return f"  · {text}" if text else ""

    def rows(self) -> list[Row]:
        rows: list[Row] = []
        for kind in KINDS:
            backend = self.app.backends[kind]
            try:
                backend.check_supported()
            except Unsupported:
                continue
            identity = backend.live_identity()
            live_print = identity.fingerprint(kind) if identity else None
            saved = self.app.profiles.of_kind(kind)
            if identity is None:
                state = "logged out"
            elif any(p.fingerprint == live_print for p in saved):
                state = "live"
            else:
                state = f"live: {identity.describe()} (not saved, press s)"
            if self.app.journals.rescues(kind):
                state += " · ! needs attention, run status"
            rows.append(Row(kind, f"{TITLES[kind]} — {state}"))
            rows.extend(
                Row(
                    kind,
                    f"{p.label}  {p.identity.describe()}{self._usage_text(p.fingerprint)}",
                    p,
                    p.fingerprint == live_print,
                )
                for p in saved
            )
        return rows

    def _selectable(self, rows: list[Row]) -> list[int]:
        return [i for i, row in enumerate(rows) if not row.header]

    def selected(self, rows: list[Row]) -> Row | None:
        choices = self._selectable(rows)
        if not choices:
            return None
        self.cursor = max(0, min(self.cursor, len(choices) - 1))
        return rows[choices[self.cursor]]

    def _kind_here(self, rows: list[Row]) -> str | None:
        row = self.selected(rows)
        if row:
            return row.kind
        return rows[0].kind if rows else None

    # -- keys --------------------------------------------------------------

    def handle(self, key: str) -> bool:
        """Act on one key. False means close the picker."""
        if key in ("q", "esc"):
            return False
        rows = self.rows()
        row = self.selected(rows)
        if key in ("j", "down"):
            self.cursor += 1
        elif key in ("k", "up"):
            self.cursor = max(0, self.cursor - 1)
        elif key == "enter" and row and row.profile:
            label = row.profile.label
            self._attempt(
                lambda force: self.app.switcher.switch(
                    row.kind, row.profile.id if row.profile else "", force=force
                ),
                f"switching to {label}…",
            )
        elif key == "u" and (kind := self._kind_here(rows)):
            self._undo(kind)
        elif key == "s" and (kind := self._kind_here(rows)):
            self._save(kind)
        elif key == "r" and row and row.profile:
            self._rename(row.profile)
        elif key == "x" and row and row.profile:
            self._delete(row.profile, row.live)
        return True

    def _undo(self, kind: str) -> None:
        self._attempt(lambda force: self.app.switcher.undo(kind, force=force), "switching back…")

    def _attempt(self, action: Callable[[bool], Outcome], doing: str = "switching…") -> None:
        self.progress(doing)
        try:
            try:
                outcome = action(False)
            except NeedsConfirmation as exc:
                if not self.confirm(exc.message + ". Switch anyway?"):
                    self.message = "not switched"
                    return
                outcome = action(True)
        except AuthPickerError as exc:
            self.message = exc.message
            return
        if outcome.status == "already":
            self.message = f"already on {outcome.label}"
            return
        notes = list(outcome.notes)
        if outcome.codex_server_stale:
            notes.append(self._codex_restart(outcome.label))
        joined = "; ".join(notes)
        self.message = f"switched to {outcome.label}" + (f" ({joined})" if joined else "")
        herdr.stamp_soon()  # herdr refreshes the badges; nobody waits for it
        kind = outcome.kind

        def pinned() -> None:
            for note in self.app.switcher.pinned_notes(kind):
                self._note(note)

        self._background(pinned)

    def _codex_restart(self, label: str) -> str:
        policy = self.app.config.codex_restart
        if policy == "ask":
            policy = (
                "always"
                if self.confirm(
                    f"Restart Codex's background server so running sessions use {label}? "
                    "Open conversations are saved; a reply in progress is cut off."
                )
                else "never"
            )
        if policy != "always":
            return "Codex keeps the previous account until its background server restarts"
        self.progress("restarting Codex's background server…")
        restart = getattr(self.app.backends["codex"], "restart_server", None)
        if restart is None:
            return "Codex keeps the previous account until its background server restarts"
        try:
            restart()
        except AuthPickerError as exc:
            return exc.message
        return "Codex's background server restarted"

    def _save(self, kind: str) -> None:
        identity = self.app.backends[kind].live_identity()
        suggested = (identity.email or identity.account_id).split("@")[0] if identity else ""
        name = self.ask(f"Name this {TITLES[kind]} login", suggested)
        if not name:
            return
        try:
            profile = self.app.switcher.save(kind, name)
        except AuthPickerError as exc:
            self.message = exc.message
            return
        self.message = f"saved as {profile.label}"
        herdr.stamp_soon()

    def _rename(self, profile: Profile) -> None:
        name = self.ask(f"New name for {profile.label}", profile.label)
        if not name or name == profile.label:
            return
        try:
            self.message = f"renamed to {self.app.profiles.rename(profile, name).label}"
        except AuthPickerError as exc:
            self.message = exc.message

    def _delete(self, profile: Profile, live: bool) -> None:
        note = (
            "It is logged in now; the login itself stays."
            if live
            else "It is not logged in: this deletes the ONLY copy of that login."
        )
        if not self.confirm(f"Delete {profile.label}? {note}"):
            return
        try:
            self.app.profiles.delete(profile)
        except AuthPickerError as exc:
            self.message = exc.message
            return
        self.message = f"deleted {profile.label}"


# -- drawing --------------------------------------------------------------------


class Screen(Protocol):
    def getmaxyx(self) -> tuple[int, int]: ...
    def erase(self) -> None: ...
    def addnstr(self, y: int, x: int, text: str, n: int, attr: int = 0) -> None: ...
    def refresh(self) -> None: ...


def draw(screen: Screen, picker: Picker, rows: list[Row], attrs: dict[str, int]) -> None:
    """Paint one frame. Never writes outside the window, whatever its size."""
    height, width = screen.getmaxyx()
    screen.erase()
    if height < 1 or width < 2:  # noqa: PLR2004 - nothing fits; draw nothing
        return

    def put(y: int, text: str, attr: int = 0) -> None:
        if 0 <= y < height:
            # The bottom-right cell cannot be written without curses raising.
            with contextlib.suppress(Exception):
                screen.addnstr(y, 0, text.ljust(width - 1), width - 1, attr)

    put(0, "ACCOUNTS", attrs.get("bold", 0))
    put(1, HELP, attrs.get("dim", 0))
    selected = picker.selected(rows)
    y = 3
    for row in rows:
        if y >= height - 1:
            break
        if row.header:
            y += 1 if y > 3 else 0  # noqa: PLR2004 - a blank line between kinds
            put(y, row.text, attrs.get("bold", 0))
        else:
            mark = "●" if row.live else " "
            attr = attrs.get("reverse", 0) if row is selected else 0
            put(y, f" {mark} {row.text}", attr)
        y += 1
    if picker.message:
        put(height - 1, picker.message, attrs.get("bold", 0))
    screen.refresh()


_KEYS = {10: "enter", 13: "enter", 27: "esc"}
MAX_CODEPOINT = 0x110000


class _Terminal:
    """The curses side of the picker: the bottom line, prompts, confirmations."""

    def __init__(self, stdscr: Any, curses: Any) -> None:
        self.stdscr = stdscr
        self.curses = curses

    def bottom(self, text: str) -> None:
        height, width = self.stdscr.getmaxyx()
        with contextlib.suppress(self.curses.error):
            self.stdscr.addnstr(height - 1, 0, text.ljust(width - 1), width - 1, self.curses.A_BOLD)

    def progress(self, text: str) -> None:
        self.bottom(text)
        self.stdscr.refresh()

    def confirm(self, question: str) -> bool:
        self.bottom(question + "  [y/N]")
        self.stdscr.timeout(-1)
        try:
            return self.stdscr.getch() in (ord("y"), ord("Y"))
        finally:
            self.stdscr.timeout(REFRESH_MS)

    def prompt(self, question: str, initial: str) -> str | None:
        curses, buffer = self.curses, list(initial)
        self.stdscr.timeout(-1)
        try:
            while True:
                width = self.stdscr.getmaxyx()[1]
                self.bottom(f"{question}: {''.join(buffer)}_"[-(width - 1) :])
                key = self.stdscr.get_wch()  # whole characters, not UTF-8 bytes
                if key in ("\x1b", 27):
                    return None
                if key in ("\n", "\r", curses.KEY_ENTER):
                    return "".join(buffer).strip()
                if key in ("\x7f", "\b", curses.KEY_BACKSPACE):
                    if buffer:
                        buffer.pop()
                elif isinstance(key, str) and key.isprintable():
                    buffer.append(key)
        finally:
            self.stdscr.timeout(REFRESH_MS)


def run(app: App) -> int:
    import curses  # noqa: PLC0415 - only the overlay needs curses

    def main(stdscr: Any) -> None:
        with contextlib.suppress(curses.error):
            curses.curs_set(0)
        attrs = {"bold": curses.A_BOLD, "dim": curses.A_DIM, "reverse": curses.A_REVERSE}
        special = {curses.KEY_DOWN: "down", curses.KEY_UP: "up", curses.KEY_ENTER: "enter", **_KEYS}
        term = _Terminal(stdscr, curses)
        picker = Picker(app, term.prompt, term.confirm, term.progress)
        try:
            while True:
                draw(stdscr, picker, picker.rows(), attrs)  # from what is on disk: no waiting
                picker.refresh_usage_soon()
                # Poll faster while background work may change what is shown.
                stdscr.timeout(POLL_BUSY_MS if picker.busy else REFRESH_MS)
                try:
                    code = stdscr.getch()
                except KeyboardInterrupt:
                    return
                if code == -1:
                    continue
                key = special.get(code) or (chr(code) if 0 <= code < MAX_CODEPOINT else "")
                if not picker.handle(key):
                    return
        finally:
            picker.finish()

    curses.wrapper(main)
    return 0
