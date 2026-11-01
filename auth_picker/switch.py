"""The switch transaction, undo, and crash recovery (docs/design.md sections 5-8).

Lock order: the machine-wide store lock, then our state lock, then the CLI's
own locks around the actual write. Before anything is written, the login
that is live now is saved durably: in its profile, and as the transaction's
pre-image. A switch therefore never destroys the newest copy of a login.
"""

from __future__ import annotations

import contextlib
import json
import os
import time
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Any

from auth_picker import paths, procscan
from auth_picker.backends.base import Backend, Snapshot, validate
from auth_picker.errors import AuthPickerError, Conflict, StaleSnapshot
from auth_picker.foreignlock import Held
from auth_picker.fsutil import read_private, secure_dir, write_private
from auth_picker.journal import Journal, JournalStore
from auth_picker.lock import FileLock
from auth_picker.profiles import MAX_LABEL, Profile, ProfileError, Profiles
from auth_picker.redact import Sensitive

# A token this close to expiry may be renewed by a running session any moment.
RENEWAL_WINDOW_S = 600
MAX_ATTEMPTS = 3


class SwitchError(AuthPickerError):
    """A switch that did not happen. The message says what state things are in."""


class NeedsConfirmation(AuthPickerError):
    """A switch that is probably fine but risky right now; retry with force."""

    exit_code = 3


@dataclass(frozen=True)
class Outcome:
    kind: str
    status: str  # "switched" | "already"
    label: str
    describe: str
    notes: list[str] = field(default_factory=list)


class Switcher:
    def __init__(
        self,
        profiles: Profiles,
        journals: JournalStore,
        *,
        lock_timeout: float = 5.0,
        scan: Callable[[str], procscan.Sessions] = procscan.sessions,
        clock: Callable[[], float] = time.time,
        store_lock_path: Callable[[str], str] = paths.store_lock_path,
    ) -> None:
        self.profiles = profiles
        self.journals = journals
        self.store = profiles.store
        self.backends = profiles.backends
        self.lock_timeout = lock_timeout
        self.scan = scan
        self.clock = clock
        self.store_lock_path = store_lock_path

    # -- public ------------------------------------------------------------

    def switch(self, kind: str, name: str, *, force: bool = False) -> Outcome:
        backend = self.backends[kind]
        with self._locked(backend):
            profile = self.profiles.find(kind, name)
            secret, target = self.profiles.secret(profile)
            outcome = self._switch(backend, secret, target, profile.label, force=force)
            if outcome.status == "switched":
                self.profiles.mark_used(profile)
            return outcome

    def next(self, kind: str, *, force: bool = False) -> Outcome:
        mine = self.profiles.of_kind(kind)
        if not mine:
            raise SwitchError("no-profiles", f"no saved {kind} logins yet; save one first")
        live = self.backends[kind].read_live()
        current = (
            [p.fingerprint for p in mine].index(live.fingerprint)
            if live and any(p.fingerprint == live.fingerprint for p in mine)
            else -1
        )
        return self.switch(kind, mine[(current + 1) % len(mine)].id, force=force)

    def undo(self, kind: str, *, force: bool = False) -> Outcome:
        backend = self.backends[kind]
        with self._locked(backend):
            secret = self.store.get(f"undo:{kind}")
            if secret is None:
                raise SwitchError("no-undo", f"nothing to undo for {kind}")
            target = backend.parse_secret(secret)
            saved = self.profiles.by_fingerprint(kind, target.fingerprint)
            label = saved.label if saved else target.identity.describe()
            return self._switch(backend, secret, target, label, force=force)

    def save(self, kind: str, label: str | None = None) -> Profile:
        """Save the live login as a new profile."""
        backend = self.backends[kind]
        with self._locked(backend):
            live = backend.read_live()
            if live is None:
                raise SwitchError("logged-out", f"{backend.title}: nobody is logged in")
            self._check_contamination(backend, live)
            identity = live.identity
            name = label or (identity.email or identity.account_id).split("@")[0]
            profile = self.profiles.create(name, live)
            self._write_expected(kind, live.fingerprint)
            return profile

    def sync(self, kind: str) -> Profile:
        """Update the saved copy of the live login from the live store."""
        backend = self.backends[kind]
        with self._locked(backend):
            live = backend.read_live()
            if live is None:
                raise SwitchError("logged-out", f"{backend.title}: nobody is logged in")
            self._check_contamination(backend, live)
            saved = self.profiles.by_fingerprint(kind, live.fingerprint)
            if saved is None:
                raise SwitchError("unsaved", f"{backend.title}: the live login is not saved yet")
            updated = self.profiles.update_secret(saved, live)
            self._write_expected(kind, live.fingerprint)
            return updated

    def expected_fingerprint(self, kind: str) -> str | None:
        expected = self._read_expected(kind)
        value = expected.get("fingerprint") if expected else None
        return value if isinstance(value, str) else None

    def recover(self, kind: str) -> str | None:
        """Finish or undo an interrupted switch. Returns what happened, if anything."""
        backend = self.backends[kind]
        with self._store_locks(backend):
            journal = self.journals.current(kind)
            return self._resolve(backend, journal) if journal else None

    # -- locking -----------------------------------------------------------

    @contextlib.contextmanager
    def _store_locks(self, backend: Backend) -> Iterator[None]:
        path = self.store_lock_path(backend.store_id)
        secure_dir(os.path.dirname(path))
        with FileLock(path, self.lock_timeout, "another switch"), self.profiles.locked():
            yield

    @contextlib.contextmanager
    def _locked(self, backend: Backend) -> Iterator[None]:
        """Store locks, plus: nothing pending, nothing unresolved, a setup we support."""
        with self._store_locks(backend):
            journal = self.journals.current(backend.kind)
            if journal is not None:
                self._resolve(backend, journal)
            rescues = self.journals.rescues(backend.kind)
            if rescues:
                raise SwitchError(
                    "rescue-open",
                    f"{backend.title} has an unresolved problem ({rescues[0].reason}); "
                    "see `status`, and clear it before switching",
                )
            backend.check_supported()
            yield

    # -- the transaction ---------------------------------------------------

    def _switch(
        self, backend: Backend, secret: Sensitive, target: Snapshot, label: str, *, force: bool
    ) -> Outcome:
        issues = validate(target, self.clock())
        hard = [i.message for i in issues if i.hard]
        if hard:
            raise SwitchError("invalid-target", f"{label}: " + "; ".join(hard))
        notes = [i.message for i in issues if not i.hard]
        describe = target.identity.describe()
        for _ in range(MAX_ATTEMPTS):
            live = backend.read_live()
            if live is not None:
                self._check_contamination(backend, live)
                if live.fingerprint == target.fingerprint:
                    return Outcome(backend.kind, "already", label, describe)
                if backend.renewal_guard and not force:
                    self._renewal_guard(backend, live)
                notes += self._persist_outgoing(backend, live)
            try:
                with backend.locks(self.lock_timeout) as held:
                    result = self._install(
                        backend, secret=secret, target=target, label=label, live=live, held=held
                    )
            except _Retry:
                continue
            if result is not None:
                raise result
            return Outcome(backend.kind, "switched", label, describe, notes)
        raise SwitchError("unsettled", f"{backend.title}'s login kept changing; try again")

    def _install(
        self,
        backend: Backend,
        *,
        secret: Sensitive,
        target: Snapshot,
        label: str,
        live: Snapshot | None,
        held: Held,
    ) -> SwitchError | None:
        journal = Journal(
            txid=uuid.uuid4().hex,
            kind=backend.kind,
            phase="begun",
            target_label=label,
            target_fingerprint=target.fingerprint,
            target_components=backend.components(target),
            pre_fingerprint=live.fingerprint if live else None,
            pre_components=backend.components(live) if live else {},
        )
        self.journals.begin(journal, live.secret if live else None)
        try:
            journal.phase = "installing"
            self.journals.write(journal)
            backend.install(secret, live, held)
            after = backend.read_live()
        except StaleSnapshot:
            # Nothing was written: start again from a fresh read, which saves
            # the newer login before anything replaces it.
            self.journals.close(journal)
            raise _Retry from None
        except Conflict:
            if self._resolve(backend, journal, held) == "aborted":
                raise _Retry from None
            return SwitchError(
                "conflict", f"{backend.title}'s login changed mid-switch; see `status`"
            )
        except BaseException:
            self._resolve(backend, journal, held)
            raise
        if after is None or (after.fingerprint, after.cred_hash) != (
            target.fingerprint,
            target.cred_hash,
        ):
            outcome = self._resolve(backend, journal, held)
            put_back = "the previous login was put back" if outcome == "aborted" else "see `status`"
            return SwitchError("did-not-take", f"the new login did not take; {put_back}")
        self._commit(journal)
        return None

    def _commit(self, journal: Journal) -> None:
        pre = self.journals.pre_secret(journal)
        if pre is not None:
            self.store.put(f"undo:{journal.kind}", pre)
        self._write_expected(journal.kind, journal.target_fingerprint)
        self.journals.close(journal)

    # -- recovery ----------------------------------------------------------

    def _resolve(self, backend: Backend, journal: Journal, held: Held | None = None) -> str:
        """Decide what an interrupted switch left behind, and settle it (design §6)."""
        if held is None:
            with backend.locks(self.lock_timeout) as taken:
                return self._resolve(backend, journal, taken)
        pre = self.journals.pre_secret(journal)
        try:
            live: Snapshot | None = backend.read_live()
            now = backend.components(live) if live else {}
        except AuthPickerError:
            live, now = None, {"unreadable": ""}
        if journal.phase == "begun" or now == journal.pre_components:
            self.journals.close(journal)
            return "aborted"
        if now == journal.target_components:
            self._commit(journal)
            return "committed"
        mixed = (
            pre is not None
            and live is not None
            and all(
                now.get(k) in (journal.pre_components[k], journal.target_components[k])
                for k in journal.pre_components
            )
        )
        if mixed and pre is not None and live is not None:
            backend.install(pre, live, held)
            restored = backend.read_live()
            if restored is not None and backend.components(restored) == journal.pre_components:
                self.journals.close(journal)
                return "aborted"
        kept: list[tuple[str, Sensitive, str, str | None]] = []
        if pre is not None:
            described = ""
            with contextlib.suppress(AuthPickerError):
                described = backend.parse_secret(pre).identity.describe()
            kept.append(("login before the switch", pre, described, journal.pre_fingerprint))
        if live is not None:
            kept.append(
                ("login found afterwards", live.secret, live.identity.describe(), live.fingerprint)
            )
        self.journals.open_rescue(
            journal.kind, f"a switch to {journal.target_label} was interrupted", kept
        )
        self.journals.close(journal)
        return "rescued"

    # -- checks ------------------------------------------------------------

    def _check_contamination(self, backend: Backend, live: Snapshot) -> None:
        for profile in self.profiles.of_kind(backend.kind):
            if profile.fingerprint != live.fingerprint and profile.holds(
                live.cred_hash, live.refresh_hash
            ):
                reason = (
                    f"the live login says it is {live.identity.describe()} "
                    f"but holds {profile.label}'s tokens"
                )
                self.journals.open_rescue(
                    backend.kind,
                    reason,
                    [("live login", live.secret, live.identity.describe(), live.fingerprint)],
                )
                raise SwitchError("contaminated", f"{reason}; nothing was changed, see `status`")

    def _renewal_guard(self, backend: Backend, live: Snapshot) -> None:
        expires = live.access_expires_at
        if expires is None or expires - self.clock() > RENEWAL_WINDOW_S:
            return
        running = self.scan(backend.kind).running
        if running:
            raise NeedsConfirmation(
                "renewal",
                f"{running} running {backend.title} session(s) may renew this login at any "
                "moment, which a switch now could strand; wait a minute or switch with --force",
            )

    def _persist_outgoing(self, backend: Backend, live: Snapshot) -> list[str]:
        """Save the live login before replacing it (invariant I1)."""
        saved = self.profiles.by_fingerprint(backend.kind, live.fingerprint)
        if saved is None:
            label = self._autosave_label(backend.kind, live)
            self.profiles.create(label, live)
            return [f"saved the outgoing login as {label!r}"]
        expected = self._read_expected(backend.kind)
        if expected is not None and expected.get("fingerprint") != live.fingerprint:
            return [
                f"{saved.label} was logged in outside auth-picker, so its saved copy was "
                "left as is; the live login is kept for undo (run sync to update it)"
            ]
        self.profiles.update_secret(saved, live)
        return []

    def _autosave_label(self, kind: str, live: Snapshot) -> str:
        base = f"autosaved {live.identity.email or live.identity.account_id[:8]}"[: MAX_LABEL - 3]
        taken = {p.label.casefold() for p in self.profiles.of_kind(kind)}
        label, n = base, 2
        while label.casefold() in taken:
            label, n = f"{base}-{n}", n + 1
        if len(label) > MAX_LABEL:
            raise ProfileError("label", "could not name the outgoing login")
        return label

    def _expected_path(self, kind: str) -> str:
        return os.path.join(self.profiles.state_dir, f"expected-{kind}.json")

    def _read_expected(self, kind: str) -> dict[str, Any] | None:
        data = read_private(self._expected_path(kind), 4096)
        return json.loads(data) if data else None

    def _write_expected(self, kind: str, fingerprint: str) -> None:
        body = {"fingerprint": fingerprint, "at": self.clock()}
        write_private(self._expected_path(kind), json.dumps(body).encode())


class _Retry(Exception):
    """The live login moved before anything was written; start the switch again."""
