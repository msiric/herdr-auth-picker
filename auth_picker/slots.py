"""Per-session Claude accounts: lending a profile to a slot, and taking it back.

A slot is a second Claude store for one account (design §14). Sessions
started with the slot's directory in CLAUDE_SECURESTORAGE_CONFIG_DIR use it,
and every session pinned to that account shares it.

I8: an account is live in at most one store, because two live copies of a
login spend each other's refresh tokens. Every change here happens under the
main Claude store's lock, so it is serialised against switches.
"""

from __future__ import annotations

import json
import os
import shutil
import time
import uuid
from collections.abc import Callable
from dataclasses import asdict, dataclass, replace
from typing import TYPE_CHECKING, Any

from auth_picker import procscan
from auth_picker.backends.base import Snapshot, canonical, secret_object, validate
from auth_picker.backends.claude import SLOT_VAR, ClaudeBackend, ClaudeSlot
from auth_picker.errors import AuthPickerError, ProcessFailed
from auth_picker.fsutil import read_private, secure_dir, write_private
from auth_picker.profiles import Profile, ProfileError
from auth_picker.redact import Sensitive

if TYPE_CHECKING:
    from auth_picker.switch import Switcher

KIND = "claude"
MAX_INDEX_BYTES = 256 * 1024


class SlotError(AuthPickerError):
    pass


@dataclass(frozen=True)
class Slot:
    profile_id: str
    state: str  # "lending" (being written) | "lent"
    lent_at: float
    # The process moving a session into the slot, until that session runs.
    # While it is alive the slot counts as in use, even with no session yet.
    mover: int | None = None
    # In use until then, too: a restart failed and the user was shown the
    # command to start the session themselves.
    held_until: float | None = None


Users = dict[str, list[int]]  # slot directory -> Claude pids using it


class Slots:
    def __init__(
        self,
        switcher: Switcher,
        *,
        users: Callable[[list[str]], Users] | None = None,
        clock: Callable[[], float] = time.time,
        make_slot: Callable[[str], ClaudeSlot] = ClaudeSlot,
        alive: Callable[[int], bool] = procscan.alive,
    ) -> None:
        self.switcher = switcher
        self.profiles = switcher.profiles
        self.backend = switcher.backends[KIND]
        self.root = os.path.join(self.profiles.state_dir, "slots")
        self.index_path = os.path.join(self.profiles.state_dir, "slots.json")
        self._users = users or (lambda dirs: procscan.slot_users(SLOT_VAR, dirs))
        self.clock = clock
        self.make_slot = make_slot
        self.alive = alive

    # -- the index ---------------------------------------------------------

    def all(self) -> list[Slot]:
        data = read_private(self.index_path, MAX_INDEX_BYTES)
        if not data:
            return []
        try:
            raw = json.loads(data)
            slots = [
                Slot(
                    str(uuid.UUID(s["profile_id"])),
                    str(s["state"]),
                    float(s["lent_at"]),
                    None if s.get("mover") is None else int(s["mover"]),
                    None if s.get("held_until") is None else float(s["held_until"]),
                )
                for s in raw["slots"]
            ]
        except (ValueError, KeyError, TypeError) as exc:
            raise SlotError("slots-index", f"{self.index_path} is damaged; not guessing") from exc
        if any(s.state not in ("lending", "lent") for s in slots):
            raise SlotError("slots-index", f"{self.index_path} has an unknown state")
        return slots

    def get(self, profile_id: str) -> Slot | None:
        return next((s for s in self.all() if s.profile_id == profile_id), None)

    def _write(self, slots: list[Slot]) -> None:
        secure_dir(self.profiles.state_dir)
        body = {"version": 1, "slots": [asdict(s) for s in slots]}
        write_private(self.index_path, json.dumps(body).encode())

    def _put(self, slot: Slot) -> None:
        self._write([s for s in self.all() if s.profile_id != slot.profile_id] + [slot])

    def _drop(self, profile_id: str) -> None:
        self._write([s for s in self.all() if s.profile_id != profile_id])

    @property
    def claude_dir(self) -> str:
        """Claude's config dir, where it keeps conversations."""
        if not isinstance(self.backend, ClaudeBackend):
            raise SlotError("slot-kind", "per-session accounts need Claude's own backend")
        return self.backend.paths.config_dir

    def directory(self, profile_id: str) -> str:
        # Recomputed from the id every time: a path is never read from disk.
        return os.path.join(self.root, str(uuid.UUID(profile_id)))

    # -- who uses what -----------------------------------------------------

    def users(self) -> dict[str, list[int]]:
        """profile id -> pids of running Claude sessions in its slot.

        Raises SlotError when that cannot be told: callers then treat every
        slot as in use (fail closed).
        """
        slots = self.all()
        if not slots:
            return {}
        dirs = {self.directory(s.profile_id): s.profile_id for s in slots}
        try:
            found = self._users(list(dirs))
        except (OSError, ProcessFailed) as exc:
            raise SlotError("slot-scan", "could not tell which sessions use which account") from exc
        return {dirs[d]: pids for d, pids in found.items() if d in dirs}

    def in_use(self, slot: Slot, users: dict[str, list[int]]) -> bool:
        moving = slot.mover is not None and self.alive(slot.mover)
        held = slot.held_until is not None and self.clock() < slot.held_until
        return bool(users.get(slot.profile_id)) or moving or held

    def profile_of_dir(self, directory: str) -> str | None:
        return next(
            (s.profile_id for s in self.all() if self.directory(s.profile_id) == directory), None
        )

    def dirs(self) -> list[str]:
        return [self.directory(s.profile_id) for s in self.all()]

    def snapshot(self, profile_id: str) -> Snapshot | None:
        """The login a slot holds now, under its profile's identity (to read its usage)."""
        slot = self.get(profile_id)
        if slot is None or slot.state != "lent":
            return None
        credentials = self.make_slot(self.directory(profile_id)).read()
        if credentials is None:
            return None
        secret, _ = self.profiles.secret(self.profiles.get(profile_id))
        obj = secret_object(secret, KIND)
        obj["credentials"] = credentials
        return self.backend.parse_secret(Sensitive(canonical(obj)))

    # -- lending -----------------------------------------------------------

    def lend(self, profile: Profile) -> str:
        """Give ``profile``'s login a slot of its own; returns the slot directory.

        The slot counts as in use while this process lives, until ``release``:
        a session is about to start in it.
        """
        mover = os.getpid()
        if profile.kind != KIND:
            raise SlotError("slot-kind", "only Claude sessions can have an account of their own")
        with self.switcher._locked(self.backend):
            profile = self.profiles.get(profile.id)
            live = self.backend.live_identity()
            if live is not None and live.fingerprint(KIND) == profile.fingerprint:
                raise SlotError("slot-main", f"{profile.label} is the main account; no slot needed")
            directory = self.directory(profile.id)
            existing = self.get(profile.id)
            if existing is not None and existing.state == "lent":
                self._put(Slot(profile.id, "lent", self.clock(), mover))
                return directory
            _, snapshot = self.profiles.secret(profile)
            hard = [i.message for i in validate(snapshot, self.clock()) if i.hard]
            if hard:
                raise SlotError("invalid-target", f"{profile.label}: " + "; ".join(hard))
            credentials = secret_object(snapshot.secret, KIND)["credentials"]
            self._put(Slot(profile.id, "lending", self.clock(), mover))
            secure_dir(self.root)
            secure_dir(directory)
            self.make_slot(directory).write(credentials)
            self._put(Slot(profile.id, "lent", self.clock(), mover))
            return directory

    def release(self, profile_id: str, hold_s: float = 0.0) -> None:
        """This process is done starting a session in the slot.

        ``hold_s``: it failed, so keep the slot that long for a manual start.
        """
        with self.switcher._store_locks(self.backend):
            slot = self.get(profile_id)
            if slot is not None and slot.mover == os.getpid():
                held = self.clock() + hold_s if hold_s else None
                self._put(replace(slot, mover=None, held_until=held))

    # -- returning ---------------------------------------------------------

    def make_way(self, profile: Profile) -> None:
        """Before the main store takes ``profile``'s account: return its slot, or refuse.

        The caller holds the main store's lock.
        """
        slot = self.get(profile.id)
        if slot is None:
            return
        users = self.users()
        if self.in_use(slot, users):
            count = len(users.get(profile.id, []))
            who = f"{count} pinned session(s)" if count else "a session that is starting"
            raise SlotError(
                "slot-in-use",
                f"{profile.label} is in use by {who}; move them back to the main account "
                "first (`p` on the main account in the picker), or close them",
            )
        message, problem = self._return(slot)
        if problem:
            raise SlotError("slot-problem", f"{message}; nothing was switched, see `status`")

    def give_back(self, profile_id: str) -> str | None:
        """Return one slot if nothing uses it. What happened, or None if it was in use."""
        with self.switcher._store_locks(self.backend):
            slot = self.get(profile_id)
            if slot is None:
                return None
            if self.in_use(slot, self.users()):
                return None
            return self._return(slot)[0]

    def tidy(self) -> list[str]:
        """Return every slot nothing uses (at herdr start, and `cleanup`)."""
        done = []
        with self.switcher._store_locks(self.backend):
            slots = self.all()
            if not slots:
                return []
            try:
                users = self.users()
            except SlotError:
                return []
            for slot in slots:
                if self.in_use(slot, users):
                    continue
                try:
                    done.append(self._return(slot)[0])
                except AuthPickerError as exc:
                    done.append(exc.message)
        return done

    def _return(self, slot: Slot) -> tuple[str, bool]:
        """Put a slot's login back in its profile, then remove the slot.

        Returns what happened, and whether it was a problem (the login went to
        a rescue instead). Every step can run again after a crash: the profile
        update is skipped when it already holds this login, a rescue is opened
        before the slot is deleted, and deleting is idempotent.
        """
        directory = self.directory(slot.profile_id)
        holder = self.make_slot(directory)
        try:
            profile: Profile | None = self.profiles.get(slot.profile_id)
        except ProfileError:
            profile = None
        label = profile.label if profile else "a deleted profile"
        message, problem = f"{label}: its own-account slot is closed", False
        if slot.state == "lent":
            secure_dir(directory)  # Claude's lock dirs go inside it
            with holder.locks(self.switcher.lock_timeout):
                credentials = holder.read()
                if credentials is None:
                    message = (
                        f"{label}: its slot held no working login (Claude had given it up); "
                        "the saved copy may be out of date"
                    )
                else:
                    trouble = self._keep(profile, label, credentials)
                    if trouble:
                        message, problem = f"{label}'s own-account slot: {trouble}", True
                holder.delete()
        else:
            holder.delete()  # never lent: the profile is still the newest copy
        # The entry goes before the directory: an entry whose directory is
        # gone could not be locked again, while a leftover empty dir is harmless.
        self._drop(slot.profile_id)
        self._remove_dir(directory)
        return message, problem

    def _keep(self, profile: Profile | None, label: str, credentials: dict[str, Any]) -> str | None:
        """The slot's login is the newest generation of its account (I1): keep it.

        Into its profile; the generation before is kept there for `revert`.
        Returns why not, when it can't be.
        """
        if profile is None:
            return self._rescue(label, credentials, "its profile was deleted while it was lent")
        secret, saved = self.profiles.secret(profile)
        obj = secret_object(secret, KIND)
        obj["credentials"] = credentials
        snapshot = self.backend.parse_secret(Sensitive(canonical(obj)))
        if snapshot.cred_hash == saved.cred_hash:
            return None
        other = next(
            (
                p
                for p in self.profiles.of_kind(KIND)
                if p.id != profile.id and p.holds(snapshot.cred_hash, snapshot.refresh_hash)
            ),
            None,
        )
        if other is not None:
            # Already saved as `other`; putting it under this profile would
            # cross-write accounts (T5), so it is left out.
            return (
                f"it held {other.label}'s login (already saved there), so {label}'s saved "
                "copy was left as it was and may be out of date"
            )
        self.profiles.update_secret(profile, snapshot)
        return None

    def _rescue(self, label: str, credentials: dict[str, Any], reason: str) -> str:
        secret = Sensitive(canonical(credentials))
        self.switcher.journals.open_rescue(
            KIND,
            f"{label}'s own-account slot: {reason}",
            [("login found in the slot", secret, f"{label}'s slot", None)],
            cause="contaminated",
        )
        return f"{reason}; its login is kept as a rescue"

    def _remove_dir(self, directory: str) -> None:
        if os.path.islink(directory) or os.path.dirname(directory) != self.root:
            raise SlotError("slot-dir", f"{directory} is not ours; leaving it alone")
        shutil.rmtree(directory, ignore_errors=True)
