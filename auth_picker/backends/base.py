"""What every credential backend provides (docs/design.md §2)."""

from __future__ import annotations

import base64
import binascii
import contextlib
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Protocol

from auth_picker.errors import AuthPickerError
from auth_picker.foreignlock import Held
from auth_picker.redact import Sensitive

SCHEMA = 1
# A refresh token this close to expiry is treated as expired.
REFRESH_EXPIRY_MARGIN_S = 3600


class Unsupported(AuthPickerError):
    """This machine's setup is one we refuse to touch."""


class Inconsistent(AuthPickerError):
    """The live store is changing, half-written, or contradicts itself."""


@dataclass(frozen=True)
class Identity:
    """Who a login belongs to. Never secret; shown to the user."""

    account_id: str
    # Tells apart logins that share account_id: Claude's organization,
    # Codex's user within a workspace.
    subject_id: str | None = None
    email: str | None = None
    org_name: str | None = None
    plan: str | None = None

    def fingerprint(self, kind: str) -> str:
        return sha256_hex(f"{kind}|{self.account_id}|{self.subject_id or ''}".encode())

    def describe(self) -> str:
        parts = [self.email or self.account_id[:8], self.plan, self.org_name]
        return " · ".join(p for p in parts if p)


@dataclass(frozen=True)
class Snapshot:
    """One login: the secret we would save, and what we know about it."""

    kind: str
    secret: Sensitive
    identity: Identity
    fingerprint: str
    cred_hash: str
    refresh_hash: str
    access_expires_at: float | None
    refresh_expires_at: float | None
    # Backend-private record of what was read, for compare-and-swap on install.
    # None for a snapshot parsed from a saved profile.
    read: Any = field(default=None, repr=False, compare=False)


@dataclass(frozen=True)
class Issue:
    hard: bool
    code: str
    message: str


class Backend(Protocol):
    kind: str
    title: str
    # True when the CLI can renew its token mid-switch with no lock of its own
    # to stop it, so a switch near expiry asks first (design §8).
    renewal_guard: bool

    @property
    def store_id(self) -> str: ...
    def components(self, snapshot: Snapshot) -> dict[str, str]: ...
    def live_identity(self) -> Identity | None: ...

    def check_supported(self) -> None: ...
    def read_live(self) -> Snapshot | None: ...
    def parse_secret(self, secret: Sensitive) -> Snapshot: ...
    def locks(self, timeout: float) -> contextlib.AbstractContextManager[Held]: ...
    def install(self, secret: Sensitive, expect: Snapshot | None, held: Held) -> None: ...


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def load_json_object(data: bytes, what: str) -> dict[str, Any]:
    try:
        obj = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise Inconsistent("unparseable", f"{what} is not valid JSON") from None
    if not isinstance(obj, dict):
        raise Inconsistent("unparseable", f"{what} is not a JSON object")
    return obj


def jwt_claims(token: str) -> dict[str, Any]:
    """The payload of a JWT, unverified. Only for reading our own local data."""
    with contextlib.suppress(IndexError, ValueError, binascii.Error):
        payload = token.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        if isinstance(claims, dict):
            return claims
    return {}


def text(obj: dict[str, Any], key: str) -> str | None:
    value = obj.get(key)
    return value if isinstance(value, str) and value else None


def validate(snapshot: Snapshot, now: float) -> list[Issue]:
    """Local checks on a saved login before it is installed (design §5, D-VAL)."""
    issues: list[Issue] = []
    if snapshot.refresh_expires_at is not None and (
        snapshot.refresh_expires_at <= now + REFRESH_EXPIRY_MARGIN_S
    ):
        issues.append(Issue(True, "refresh-expired", "this saved login has expired; log in again"))
    if snapshot.access_expires_at is not None and snapshot.access_expires_at <= now:
        issues.append(
            Issue(False, "access-expired", "access token expired; the CLI renews it on first use")
        )
    return issues


def secret_object(secret: Sensitive, kind: str) -> dict[str, Any]:
    obj = load_json_object(secret.reveal(), f"saved {kind} login")
    if obj.get("schema") != SCHEMA or obj.get("kind") != kind:
        raise Inconsistent("schema", f"saved {kind} login has an unknown format")
    return obj
