"""Saved logins: a metadata index on disk, secrets in the secret store.

``index.json`` holds no secrets, only labels, identities and token hashes.
Each profile's secret is ``profile:<id>`` in the store, and the generation
before it is ``profile:<id>:prev`` (design §4).

Order of writes: secret first, index second. A crash then leaves at worst an
unreferenced secret, never an index entry pointing at nothing. Deleting runs
in reverse: index first, then secrets.
"""

from __future__ import annotations

import json
import os
import re
import time
import unicodedata
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass, replace
from typing import Any

from auth_picker.backends.base import Backend, Identity, Snapshot
from auth_picker.errors import AuthPickerError
from auth_picker.fsutil import read_private, secure_dir, write_private
from auth_picker.lock import FileLock
from auth_picker.redact import Sensitive
from auth_picker.secretstore.base import SecretStore

SCHEMA = 1
MAX_INDEX_BYTES = 1024 * 1024
MAX_LABEL = 40
KINDS = ("claude", "codex")
_HEX64 = re.compile(r"[0-9a-f]{64}")
MIN_ID_PREFIX = 6


class ProfileError(AuthPickerError):
    """A profile operation that cannot go ahead."""


class CorruptIndex(AuthPickerError):
    """index.json is unreadable. We refuse to rewrite what we cannot read."""


@dataclass(frozen=True)
class Profile:
    id: str
    kind: str
    label: str
    identity: Identity
    fingerprint: str
    created_at: float
    updated_at: float
    last_used_at: float | None
    refresh_expires_at: float | None
    cred_hash: str
    refresh_hash: str
    prev_cred_hash: str | None = None
    prev_refresh_hash: str | None = None

    @property
    def key(self) -> str:
        return f"profile:{self.id}"

    @property
    def prev_key(self) -> str:
        return f"profile:{self.id}:prev"

    def holds(self, cred_hash: str | None = None, refresh_hash: str | None = None) -> bool:
        """True if either generation of this profile is the one described."""
        return bool(
            (cred_hash and cred_hash in (self.cred_hash, self.prev_cred_hash))
            or (refresh_hash and refresh_hash in (self.refresh_hash, self.prev_refresh_hash))
        )


def check_label(label: str) -> str:
    label = unicodedata.normalize("NFC", label.strip())
    if not label or len(label) > MAX_LABEL:
        raise ProfileError("label", f"a name must be 1 to {MAX_LABEL} characters")
    if any(unicodedata.category(c).startswith("C") for c in label):
        raise ProfileError("label", "a name must not contain control characters")
    return label


def _entry(profile: Profile) -> dict[str, Any]:
    return asdict(profile)


def _number(value: Any, nullable: bool = False) -> float | None:
    if value is None and nullable:
        return None
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise ValueError("not a number")
    return float(value)


def _parse_entry(raw: Any) -> Profile:
    if not isinstance(raw, dict):
        raise ValueError("entry is not an object")
    identity_raw = raw["identity"]
    if not isinstance(identity_raw, dict) or not isinstance(identity_raw.get("account_id"), str):
        raise ValueError("bad identity")

    def optional(key: str) -> str | None:
        value = identity_raw.get(key)
        if value is not None and not isinstance(value, str):
            raise ValueError("bad identity")
        return value

    identity = Identity(
        account_id=identity_raw["account_id"],
        subject_id=optional("subject_id"),
        email=optional("email"),
        org_name=optional("org_name"),
        plan=optional("plan"),
    )
    profile = Profile(
        id=str(uuid.UUID(raw["id"])),
        kind=raw["kind"],
        label=check_label(raw["label"]),
        identity=identity,
        fingerprint=raw["fingerprint"],
        created_at=_number(raw["created_at"]) or 0.0,
        updated_at=_number(raw["updated_at"]) or 0.0,
        last_used_at=_number(raw.get("last_used_at"), nullable=True),
        refresh_expires_at=_number(raw.get("refresh_expires_at"), nullable=True),
        cred_hash=raw["cred_hash"],
        refresh_hash=raw["refresh_hash"],
        prev_cred_hash=raw.get("prev_cred_hash"),
        prev_refresh_hash=raw.get("prev_refresh_hash"),
    )
    if profile.kind not in KINDS:
        raise ValueError("unknown kind")
    for name in ("fingerprint", "cred_hash", "refresh_hash"):
        if not _HEX64.fullmatch(getattr(profile, name)):
            raise ValueError(f"bad {name}")
    for name in ("prev_cred_hash", "prev_refresh_hash"):
        value = getattr(profile, name)
        if value is not None and not (isinstance(value, str) and _HEX64.fullmatch(value)):
            raise ValueError(f"bad {name}")
    return profile


class Profiles:
    def __init__(
        self,
        state_dir: str,
        store: SecretStore,
        backends: dict[str, Backend],
        lock_timeout: float = 5.0,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.state_dir = state_dir
        self.store = store
        self.backends = backends
        self.lock_timeout = lock_timeout
        self.clock = clock
        self.index_path = os.path.join(state_dir, "index.json")

    # -- index -------------------------------------------------------------

    @contextmanager
    def locked(self) -> Iterator[None]:
        secure_dir(self.state_dir)
        with FileLock(os.path.join(self.state_dir, "lock"), self.lock_timeout, "another command"):
            yield

    def all(self) -> list[Profile]:
        data = read_private(self.index_path, MAX_INDEX_BYTES)
        if data is None:
            return []
        try:
            raw = json.loads(data)
            if not isinstance(raw, dict) or raw.get("schema") != SCHEMA:
                raise ValueError("unknown schema")
            profiles = [_parse_entry(e) for e in raw["profiles"]]
        except (ValueError, KeyError, TypeError, ProfileError) as exc:
            raise CorruptIndex(
                "index", f"{self.index_path} is damaged ({exc}); fix or move it aside"
            ) from None
        ids = [p.id for p in profiles]
        prints = [(p.kind, p.fingerprint) for p in profiles]
        if len(set(ids)) != len(ids) or len(set(prints)) != len(prints):
            raise CorruptIndex("index", f"{self.index_path} lists a profile twice")
        return profiles

    def _write(self, profiles: list[Profile]) -> None:
        body = {"schema": SCHEMA, "profiles": [_entry(p) for p in profiles]}
        write_private(self.index_path, (json.dumps(body, indent=2) + "\n").encode())

    def _replace(self, updated: Profile) -> None:
        self._write([updated if p.id == updated.id else p for p in self.all()])

    # -- lookups -----------------------------------------------------------

    def of_kind(self, kind: str) -> list[Profile]:
        return sorted((p for p in self.all() if p.kind == kind), key=lambda p: p.created_at)

    def get(self, profile_id: str) -> Profile:
        for profile in self.all():
            if profile.id == profile_id:
                return profile
        raise ProfileError("missing", "no such profile")

    def find(self, kind: str, name: str) -> Profile:
        """By label (case-insensitive), or by id or a unique id prefix."""
        wanted = unicodedata.normalize("NFC", name.strip()).casefold()
        mine = self.of_kind(kind)
        for profile in mine:
            if profile.label.casefold() == wanted or profile.id == name:
                return profile
        prefixed = [p for p in mine if len(name) >= MIN_ID_PREFIX and p.id.startswith(name)]
        if len(prefixed) == 1:
            return prefixed[0]
        raise ProfileError("missing", f"no {kind} profile named {name!r}")

    def by_fingerprint(self, kind: str, fingerprint: str) -> Profile | None:
        return next(
            (p for p in self.all() if p.kind == kind and p.fingerprint == fingerprint), None
        )

    def secret(self, profile: Profile) -> tuple[Sensitive, Snapshot]:
        """A profile's secret, checked against what the index says it is."""
        secret = self.store.get(profile.key)
        if secret is None:
            raise ProfileError("secret-missing", f"the saved login for {profile.label} is missing")
        snapshot = self.backends[profile.kind].parse_secret(secret)
        if (snapshot.fingerprint, snapshot.cred_hash) != (profile.fingerprint, profile.cred_hash):
            raise ProfileError(
                "secret-mismatch",
                f"the saved login for {profile.label} does not match its index entry",
            )
        return secret, snapshot

    # -- changes -----------------------------------------------------------

    def _unique_label(self, kind: str, label: str, ignore: str | None = None) -> str:
        label = check_label(label)
        taken = {p.label.casefold() for p in self.of_kind(kind) if p.id != ignore}
        if label.casefold() in taken:
            raise ProfileError("label-taken", f"a {kind} profile is already named {label!r}")
        return label

    def create(self, label: str, snapshot: Snapshot) -> Profile:
        with self.locked():
            existing = self.by_fingerprint(snapshot.kind, snapshot.fingerprint)
            if existing is not None:
                raise ProfileError("duplicate", f"this login is already saved as {existing.label}")
            now = self.clock()
            profile = Profile(
                id=str(uuid.uuid4()),
                kind=snapshot.kind,
                label=self._unique_label(snapshot.kind, label),
                identity=snapshot.identity,
                fingerprint=snapshot.fingerprint,
                created_at=now,
                updated_at=now,
                last_used_at=None,
                refresh_expires_at=snapshot.refresh_expires_at,
                cred_hash=snapshot.cred_hash,
                refresh_hash=snapshot.refresh_hash,
            )
            self.store.put(profile.key, snapshot.secret)
            self._write([*self.all(), profile])
            return profile

    def update_secret(self, profile: Profile, snapshot: Snapshot) -> Profile:
        """Store a newer generation of the same login, keeping the one before it."""
        if snapshot.fingerprint != profile.fingerprint or snapshot.kind != profile.kind:
            raise ProfileError("identity", f"that login is not {profile.label}'s account")
        with self.locked():
            current = self.get(profile.id)
            if snapshot.cred_hash == current.cred_hash:
                return current
            previous = self.store.get(current.key)
            if previous is not None:
                self.store.put(current.prev_key, previous)
            self.store.put(current.key, snapshot.secret)
            updated = replace(
                current,
                identity=snapshot.identity,
                updated_at=self.clock(),
                refresh_expires_at=snapshot.refresh_expires_at,
                cred_hash=snapshot.cred_hash,
                refresh_hash=snapshot.refresh_hash,
                prev_cred_hash=current.cred_hash if previous is not None else None,
                prev_refresh_hash=current.refresh_hash if previous is not None else None,
            )
            self._replace(updated)
            return updated

    def revert(self, profile: Profile) -> Profile:
        """Swap a profile's saved login with the generation before it."""
        with self.locked():
            current = self.get(profile.id)
            now_secret = self.store.get(current.key)
            prev_secret = self.store.get(current.prev_key)
            if prev_secret is None or now_secret is None:
                raise ProfileError("no-previous", f"{current.label} has no earlier login saved")
            previous = self.backends[current.kind].parse_secret(prev_secret)
            if previous.fingerprint != current.fingerprint:
                raise ProfileError("identity", f"the earlier login is not {current.label}'s")
            self.store.put(current.prev_key, now_secret)
            self.store.put(current.key, prev_secret)
            updated = replace(
                current,
                identity=previous.identity,
                updated_at=self.clock(),
                refresh_expires_at=previous.refresh_expires_at,
                cred_hash=previous.cred_hash,
                refresh_hash=previous.refresh_hash,
                prev_cred_hash=current.cred_hash,
                prev_refresh_hash=current.refresh_hash,
            )
            self._replace(updated)
            return updated

    def rename(self, profile: Profile, label: str) -> Profile:
        with self.locked():
            current = self.get(profile.id)
            updated = replace(current, label=self._unique_label(current.kind, label, current.id))
            self._replace(updated)
            return updated

    def mark_used(self, profile: Profile) -> Profile:
        with self.locked():
            updated = replace(self.get(profile.id), last_used_at=self.clock())
            self._replace(updated)
            return updated

    def delete(self, profile: Profile) -> None:
        with self.locked():
            current = self.get(profile.id)
            self._write([p for p in self.all() if p.id != current.id])
            self.store.delete(current.key)
            self.store.delete(current.prev_key)

    def orphans(self) -> list[str]:
        """Profile secrets no index entry refers to (left by a crash)."""
        referenced = {k for p in self.all() for k in (p.key, p.prev_key)}
        stored = self.store.keys()
        return [k for k in stored if k.startswith("profile:") and k not in referenced]
