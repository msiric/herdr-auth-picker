"""The switch transaction, undo, and crash recovery (docs/design.md sections 5-8).

Lock order: the machine-wide store lock, then our state lock, then the CLI's
own locks around the actual write. Before anything is written, the login
that is live now is saved durably: in its profile, and as the transaction's
pre-image. A switch therefore never destroys the newest copy of a login.
"""

from __future__ import annotations

import contextlib
import hashlib
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
from auth_picker.profiles import MAX_LABEL, Profile, ProfileError, Profiles, secret_hash
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
    # Codex's background server is running and still holds the previous login.
    codex_server_stale: bool = False


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
            secret = self._undo_secret(backend)
            if secret is None:
                raise SwitchError("no-undo", f"nothing to undo for {kind}")
            target = backend.parse_secret(secret)
            saved = self.profiles.by_fingerprint(kind, target.fingerprint)
            label = saved.label if saved else target.identity.describe()
            outcome = self._switch(backend, secret, target, label, force=force)
            if outcome.status == "switched" and saved is not None:
                self.profiles.mark_used(saved)
            return outcome

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
            self._write_expected(store_tag(backend), live.fingerprint)
            return profile

    def save_from(self, kind: str, source: Backend, label: str | None = None) -> Profile:
        """Save a login from another CLI home, without touching the live one.

        For Codex, this is how a second account is added safely: `codex login`
        revokes whatever login its home held, so log in under a throwaway
        CODEX_HOME and import it from there.
        """
        if source.store_id == self.backends[kind].store_id:
            raise SwitchError("same-home", "that is the live home; use save without --from")
        with self.profiles.locked():
            snapshot = source.read_live()
            if snapshot is None:
                raise SwitchError("logged-out", f"nobody is logged in under {source.store_id}")
            self._check_contamination(self.backends[kind], snapshot)
            identity = snapshot.identity
            name = label or (identity.email or identity.account_id).split("@")[0]
            return self.profiles.create(name, snapshot)

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
            self._write_expected(store_tag(backend), live.fingerprint)
            return updated

    def has_undo(self, kind: str) -> bool:
        backend = self.backends[kind]
        pointed = self._undo_pointer(store_tag(backend))
        if pointed is not None:
            return any(p.id == pointed for p in self.profiles.all())
        return any(self.store.get(key) is not None for key in _legacy_undo_keys(backend))

    def pinned_notes(self, kind: str) -> list[str]:
        """Running Claude sessions a switch cannot reach (they carry their own token).

        Separate from the switch because it costs a process scan (~150 ms):
        callers run it after the result is on screen.
        """
        if kind != "claude":
            return []
        pinned = self.scan(kind).pinned
        if not pinned:
            return []
        return [
            f"{pinned} running session(s) will not follow: {procscan.PINNING_VAR} is set in "
            "them; unset it and restart them"
        ]

    def expected_fingerprint(self, kind: str) -> str | None:
        expected = self._read_expected(store_tag(self.backends[kind]))
        value = expected.get("fingerprint") if expected else None
        return value if isinstance(value, str) else None

    def adopt(self, rid: str, item: int, name: str | None = None) -> tuple[Profile, bool]:
        """Save a login kept by a rescue as a profile. (profile, True if new)."""
        match = [r for r in self.journals.rescues() if r.rid == rid]
        if not match or not 0 <= item < len(match[0].kept):
            raise SwitchError("missing", f"no rescue {rid} with item {item}")
        rescue = match[0]
        if rescue.cause == "contaminated":
            raise SwitchError(
                "contaminated",
                "that login's tokens and identity disagree, so it cannot be saved as a "
                "profile; log in again with the CLI instead",
            )
        backend = self.backends[rescue.kind]
        with self._store_locks(backend):
            secret = self.store.get(rescue.kept[item]["key"])
            if secret is None:
                raise SwitchError("missing", "that kept login is gone")
            snapshot = backend.parse_secret(secret)
            self._check_contamination(backend, snapshot)
            saved = self.profiles.by_fingerprint(rescue.kind, snapshot.fingerprint)
            if saved is not None:
                return self.profiles.update_secret(saved, snapshot), False
            email = snapshot.identity.email or snapshot.identity.account_id[:8]
            return self.profiles.create((name or f"rescued {email}")[:MAX_LABEL], snapshot), True

    def recover(self, kind: str) -> str | None:
        """Finish or undo an interrupted switch. Returns what happened, if anything."""
        backend = self.backends[kind]
        with self._store_locks(backend):
            journal = self.journals.current(store_tag(backend))
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
            journal = self.journals.current(store_tag(backend))
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
                persisted, outgoing = self._persist_outgoing(backend, live)
                notes += persisted
            else:
                outgoing = None
            try:
                with backend.locks(self.lock_timeout) as held:
                    result = self._install(
                        backend,
                        secret=secret,
                        target=target,
                        label=label,
                        live=live,
                        held=held,
                        outgoing=outgoing,
                    )
            except _Retry:
                continue
            if result is not None:
                raise result
            after, stale = self._after(backend)
            return Outcome(backend.kind, "switched", label, describe, notes + after, stale)
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
        outgoing: Profile | None = None,
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
            store=store_tag(backend),
            # The outgoing profile was just made to hold exactly the live login,
            # so it is the pre-image; nothing more is written (I1 still holds).
            pre_profile=(
                outgoing.id
                if live is not None
                and outgoing is not None
                and outgoing.secret_hash == secret_hash(live)
                else ""
            ),
        )
        self.journals.begin(journal, live.secret if live else None)
        try:
            journal.phase = "installing"
            self.journals.write(journal)
            backend.install(secret, live, held)
            after = backend.read_live(settled=True)
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

    def _after(self, backend: Backend) -> tuple[list[str], bool]:
        """What a switch could not reach that is cheap to tell at once (V4, V5).

        Codex needs a process scan to know whether its server must restart; a
        Claude switch needs none here (see pinned_notes).
        """
        notes = []
        if backend.kind == "claude" and os.environ.get(procscan.PINNING_VAR):
            notes.append(
                f"{procscan.PINNING_VAR} is set in herdr's own environment, so sessions it "
                "starts are pinned to that token and ignore every switch"
            )
        stale = backend.kind == "codex" and self.scan(backend.kind).servers > 0
        return notes, stale

    def _commit(self, journal: Journal) -> None:
        if journal.pre_profile:
            # Undo points at the outgoing profile, which keeps that account's
            # newest login from now on; no copy is written.
            first = self._undo_pointer(journal.store) is None
            write_private(
                self._undo_path(journal.store),
                json.dumps({"profile_id": journal.pre_profile}).encode(),
            )
            if first:
                kind = journal.store.split("-", 1)[0]
                for key in (undo_key(journal.store), f"undo:{kind}"):
                    self.store.delete(key)  # the copies kept up to 1.2.0
        else:
            pre = self.journals.pre_secret(journal)
            if pre is not None:
                self.store.put(undo_key(journal.store), pre)
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(self._undo_path(journal.store))
        self._write_expected(journal.store, journal.target_fingerprint)
        self.journals.close(journal)

    def _undo_path(self, store: str) -> str:
        return os.path.join(self.profiles.state_dir, f"undo-{store}.json")

    def _undo_pointer(self, store: str) -> str | None:
        data = read_private(self._undo_path(store), 4096)
        if data is None:
            return None
        value = json.loads(data).get("profile_id")
        return value if isinstance(value, str) else None

    def _undo_secret(self, backend: Backend) -> Sensitive | None:
        pointed = self._undo_pointer(store_tag(backend))
        if pointed is not None:
            try:
                return self.profiles.secret(self.profiles.get(pointed))[0]
            except ProfileError:
                return None  # that profile was deleted
        for key in _legacy_undo_keys(backend):
            found = self.store.get(key)
            if found is not None:
                return found
        return None

    # -- recovery ----------------------------------------------------------

    def _resolve(self, backend: Backend, journal: Journal, held: Held | None = None) -> str:
        """Decide what an interrupted switch left behind, and settle it (design §6)."""
        if held is None:
            with backend.locks(self.lock_timeout) as taken:
                return self._resolve(backend, journal, taken)
        pre = self.journals.pre_secret(journal)
        # Restore only a pre-image that is still what was there: a profile used
        # as one can have moved on since (revert, adopt).
        pre_matches = False
        if pre is not None:
            with contextlib.suppress(AuthPickerError):
                pre_matches = backend.components(backend.parse_secret(pre)) == (
                    journal.pre_components
                )
        try:
            live: Snapshot | None = backend.read_live(settled=True)
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
            and pre_matches
            and live is not None
            and all(
                now.get(k) in (journal.pre_components[k], journal.target_components[k])
                for k in journal.pre_components
            )
        )
        if mixed and pre is not None and live is not None:
            backend.install(pre, live, held)
            restored = backend.read_live(settled=True)
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
                    cause="contaminated",
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

    def _persist_outgoing(self, backend: Backend, live: Snapshot) -> tuple[list[str], Profile]:
        """Save the live login before replacing it (invariant I1).

        Afterwards the returned profile holds exactly ``live``.
        """
        saved = self.profiles.by_fingerprint(backend.kind, live.fingerprint)
        if saved is None:
            label = self._autosave_label(backend.kind, live)
            created = self.profiles.create(label, live)
            return [f"saved the outgoing login as {label!r}"], created
        expected = self._read_expected(store_tag(backend))
        updated = self.profiles.update_secret(saved, live)
        # Logged in outside auth-picker: the live login is still the newest copy
        # of that account (I1), so it is saved; the copy before it is kept as
        # :prev, and `revert` goes back to it.
        outside = expected is not None and expected.get("fingerprint") != live.fingerprint
        if outside and updated.cred_hash != saved.cred_hash:
            return [
                f"{saved.label} was logged in outside auth-picker; its saved copy now "
                f"holds that login (`revert {backend.kind} {saved.label}` restores the "
                "one before)"
            ], updated
        return [], updated

    def _autosave_label(self, kind: str, live: Snapshot) -> str:
        base = f"autosaved {live.identity.email or live.identity.account_id[:8]}"[: MAX_LABEL - 3]
        taken = {p.label.casefold() for p in self.profiles.of_kind(kind)}
        label, n = base, 2
        while label.casefold() in taken:
            label, n = f"{base}-{n}", n + 1
        if len(label) > MAX_LABEL:
            raise ProfileError("label", "could not name the outgoing login")
        return label

    def _expected_path(self, store: str) -> str:
        return os.path.join(self.profiles.state_dir, f"expected-{store}.json")

    def _read_expected(self, store: str) -> dict[str, Any] | None:
        data = read_private(self._expected_path(store), 4096)
        return json.loads(data) if data else None

    def _write_expected(self, store: str, fingerprint: str) -> None:
        body = {"fingerprint": fingerprint, "at": self.clock()}
        write_private(self._expected_path(store), json.dumps(body).encode())


def store_tag(backend: Backend) -> str:
    """Names one credential store: journals, undo and expected are kept per store."""
    return f"{backend.kind}-{hashlib.sha256(backend.store_id.encode()).hexdigest()[:12]}"


def _legacy_undo_keys(backend: Backend) -> tuple[str, str]:
    """Where undo kept a copy up to 1.2.0: per store, and before that per kind."""
    return undo_key(store_tag(backend)), f"undo:{backend.kind}"


def undo_key(tag: str) -> str:
    kind, digest = tag.split("-", 1)
    return f"undo:{kind}:{digest}"


class _Retry(Exception):
    """The live login moved before anything was written; start the switch again."""
