"""Claude Code's login: a credential store plus the identity in its config file.

Verified against Claude Code 2.1.309 (docs/design.md §3, §10). The layout is
Claude's private business: unknown shapes are refused, not guessed at.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import platform
import pwd
import re
import time
import unicodedata
from dataclasses import dataclass
from typing import Any

from auth_picker.backends.base import (
    SCHEMA,
    Identity,
    Inconsistent,
    Snapshot,
    Unsupported,
    canonical,
    load_json_object,
    secret_object,
    sha256_hex,
    text,
)
from auth_picker.errors import Conflict, StaleSnapshot
from auth_picker.foreignlock import DirLock, Held, hold_all
from auth_picker.fsutil import ForeignFile, read_foreign, touch, write_foreign
from auth_picker.redact import Sensitive
from auth_picker.secretstore.keychain import read_password, write_password

TESTED_VERSIONS = ("2.1.309",)
# Keys of the stored credential that belong to the account and move with a
# profile, and keys that belong to this machine and stay put. Anything else
# is refused until someone looks at it.
ACCOUNT_KEYS = ("claudeAiOauth", "trustedDeviceToken", "trustedDeviceEnrolledAfterRefusalAtMs")
MACHINE_KEYS = ("mcpOAuth",)
MAX_CREDENTIAL_BYTES = 1024 * 1024
MAX_CONFIG_BYTES = 64 * 1024 * 1024
_SAFE_ACCOUNT = re.compile(r"[a-zA-Z0-9._-]+")
_READ_ATTEMPTS = 3


@dataclass(frozen=True)
class ClaudePaths:
    config_dir: str
    identity_file: str
    credentials_file: str
    keychain_service: str
    keychain_account: str


def _user_name(env: dict[str, str]) -> str:
    name = env.get("USER") or pwd.getpwuid(os.getuid()).pw_name
    return name if _SAFE_ACCOUNT.fullmatch(name) else "claude-code-user"


def resolve_paths(env: dict[str, str] | None = None) -> ClaudePaths:
    """Where Claude Code keeps its login, computed the way Claude computes it."""
    env = dict(os.environ) if env is None else env
    if "CLAUDE_SECURESTORAGE_CONFIG_DIR" in env:
        raise Unsupported("claude-storage-dir", "CLAUDE_SECURESTORAGE_CONFIG_DIR is not supported")
    custom = env.get("CLAUDE_CONFIG_DIR") or None
    home = env.get("HOME") or os.path.expanduser("~")
    config_dir = custom or os.path.join(home, ".claude")
    legacy = os.path.join(config_dir, ".config.json")
    try:
        legacy_in_use = os.path.isfile(legacy) and os.path.getsize(legacy) > 0
    except OSError:
        legacy_in_use = False
    identity = legacy if legacy_in_use else os.path.join(custom or home, ".claude.json")
    service = "Claude Code-credentials"
    if custom:
        normalized = unicodedata.normalize("NFC", config_dir)
        service += "-" + hashlib.sha256(normalized.encode()).hexdigest()[:8]
    return ClaudePaths(
        config_dir=config_dir,
        identity_file=identity,
        credentials_file=os.path.join(config_dir, ".credentials.json"),
        keychain_service=service,
        keychain_account=_user_name(env),
    )


@dataclass(frozen=True)
class StoreRead:
    data: bytes
    file: ForeignFile | None = None


class KeychainCredential:
    """Claude's login-keychain item (macOS)."""

    def __init__(self, service: str, account: str, keychain: str | None = None) -> None:
        self.service, self.account, self.keychain = service, account, keychain

    def read(self) -> StoreRead | None:
        value = read_password(self.service, self.account, self.keychain)
        if value is None:
            return None
        data = value.reveal()
        # security(1) prints hex instead when the data is not printable.
        if data and not data.lstrip().startswith(b"{"):
            with contextlib.suppress(ValueError):
                data = bytes.fromhex(data.decode("ascii"))
        return StoreRead(data)

    def write(self, data: bytes, expect: StoreRead | None) -> None:
        # The Keychain has no compare-and-swap. Claude's storage-write lock,
        # held by the caller, keeps Claude from writing between our read and
        # this write instead.
        del expect
        write_password(self.service, self.account, Sensitive(data), self.keychain)


class FileCredential:
    """Claude's ``.credentials.json`` (Linux)."""

    def __init__(self, path: str) -> None:
        self.path = path

    def read(self) -> StoreRead | None:
        found = read_foreign(self.path, MAX_CREDENTIAL_BYTES)
        return StoreRead(found.data, found) if found is not None else None

    def write(self, data: bytes, expect: StoreRead | None) -> None:
        try:
            write_foreign(self.path, data, expect.file if expect else None, new_mode=0o600)
        except Conflict as exc:
            raise StaleSnapshot(exc.code, exc.message) from None


CredentialStore = KeychainCredential | FileCredential


@dataclass(frozen=True)
class _Read:
    store: StoreRead | None
    identity: ForeignFile


def _claude_oauth(credentials: dict[str, Any]) -> dict[str, Any]:
    oauth = credentials.get("claudeAiOauth")
    if not (isinstance(oauth, dict) and text(oauth, "accessToken") and text(oauth, "refreshToken")):
        raise Inconsistent("claude-no-login", "Claude's credential holds no account login")
    return oauth


def _ms(value: Any) -> float | None:
    return value / 1000.0 if isinstance(value, int | float) and value > 0 else None


class ClaudeBackend:
    kind = "claude"
    title = "Claude Code"
    # Claude's own refresh lock, which a switch holds, stops a renewal mid-switch.
    renewal_guard = False

    def __init__(self, paths: ClaudePaths, store: CredentialStore | None = None) -> None:
        self.paths = paths
        self.on_macos = (
            platform.system() == "Darwin"
            if store is None
            else isinstance(store, KeychainCredential)
        )
        if store is None:
            store = (
                KeychainCredential(paths.keychain_service, paths.keychain_account)
                if self.on_macos
                else FileCredential(paths.credentials_file)
            )
        self.store = store

    # -- discovery ---------------------------------------------------------

    @property
    def store_id(self) -> str:
        p = self.paths
        return "|".join(
            (
                "claude",
                p.keychain_service,
                p.keychain_account,
                os.path.realpath(p.identity_file),
                os.path.realpath(p.credentials_file),
            )
        )

    def components(self, snapshot: Snapshot) -> dict[str, str]:
        obj = secret_object(snapshot.secret, self.kind)
        return {
            "credentials": sha256_hex(canonical(obj["credentials"])),
            "identity": sha256_hex(canonical(obj["oauth_account"])),
        }

    def check_supported(self) -> None:
        if not os.path.isdir(self.paths.config_dir):
            raise Unsupported("claude-absent", "Claude Code is not set up on this machine")

    # -- reading -----------------------------------------------------------

    def live_identity(self) -> Identity | None:
        """Who is logged in, from the config file alone: no Keychain read.

        For the badge, which runs every few seconds. Not proof of anything.
        """
        found = read_foreign(self.paths.identity_file, MAX_CONFIG_BYTES)
        if found is None:
            return None
        with contextlib.suppress(Inconsistent):
            account = load_json_object(found.data, "config").get("oauthAccount")
            if isinstance(account, dict) and text(account, "accountUuid"):
                return Identity(
                    account_id=account["accountUuid"],
                    subject_id=text(account, "organizationUuid"),
                    email=text(account, "emailAddress"),
                    org_name=text(account, "organizationName"),
                )
        return None

    def _read_identity(self) -> ForeignFile:
        found = read_foreign(self.paths.identity_file, MAX_CONFIG_BYTES)
        if found is None:
            raise Unsupported("claude-no-config", f"{self.paths.identity_file} does not exist")
        return found

    def _consistent_read(self) -> _Read:
        for _ in range(_READ_ATTEMPTS):
            first = self.store.read()
            identity = self._read_identity()
            second = self.store.read()
            same_store = (first is None) == (second is None) and (
                first is None or second is None or first.data == second.data
            )
            if same_store and self._read_identity().version == identity.version:
                return _Read(first, identity)
            time.sleep(0.05)
        raise Inconsistent("claude-changing", "Claude's login is changing right now; try again")

    def _blob(self, data: bytes) -> dict[str, Any]:
        blob = load_json_object(data, "Claude's credential")
        unknown = sorted(set(blob) - set(ACCOUNT_KEYS) - set(MACHINE_KEYS))
        if unknown:
            raise Unsupported(
                "claude-layout",
                "Claude's credential has keys this version does not know ("
                + ", ".join(unknown)
                + "); update auth-picker",
            )
        return blob

    def read_live(self) -> Snapshot | None:
        read = self._consistent_read()
        if read.store is None:
            if self.on_macos and self._login_in_credentials_file():
                raise Unsupported(
                    "claude-file-login",
                    "Claude keeps this login in .credentials.json instead of the Keychain",
                )
            config = load_json_object(read.identity.data, self.paths.identity_file)
            if isinstance(config.get("oauthAccount"), dict):
                # Claude says someone is logged in, but not where we look: our
                # idea of its store is wrong, and writing there would mislead.
                raise Unsupported(
                    "claude-store-missing",
                    "Claude's config names a logged-in account, but its credential is not in "
                    f"the Keychain item {self.paths.keychain_service!r} for account "
                    f"{self.paths.keychain_account!r}; refusing to guess",
                )
            return None
        blob = self._blob(read.store.data)
        config = load_json_object(read.identity.data, self.paths.identity_file)
        account = config.get("oauthAccount")
        if not isinstance(account, dict):
            raise Inconsistent("claude-no-identity", "Claude's config names no logged-in account")
        obj = {
            "schema": SCHEMA,
            "kind": self.kind,
            "credentials": {k: blob[k] for k in ACCOUNT_KEYS if k in blob},
            "oauth_account": account,
        }
        return self._snapshot(obj, read)

    def _login_in_credentials_file(self) -> bool:
        found = read_foreign(self.paths.credentials_file, MAX_CREDENTIAL_BYTES)
        if found is None:
            return False
        with contextlib.suppress(Inconsistent):
            return "claudeAiOauth" in load_json_object(found.data, "credentials file")
        return False

    def parse_secret(self, secret: Sensitive) -> Snapshot:
        obj = secret_object(secret, self.kind)
        credentials = obj.get("credentials")
        if not isinstance(credentials, dict) or set(credentials) - set(ACCOUNT_KEYS):
            raise Inconsistent("schema", "saved claude login has an unknown format")
        return self._snapshot(obj, None)

    def _snapshot(self, obj: dict[str, Any], read: _Read | None) -> Snapshot:
        credentials: dict[str, Any] = obj["credentials"]
        oauth = _claude_oauth(credentials)
        account: Any = obj.get("oauth_account")
        account_id = text(account, "accountUuid") if isinstance(account, dict) else None
        if not isinstance(account, dict) or account_id is None:
            raise Inconsistent("claude-no-identity", "Claude's account has no accountUuid")
        identity = Identity(
            account_id=account_id,
            subject_id=text(account, "organizationUuid"),
            email=text(account, "emailAddress"),
            org_name=text(account, "organizationName"),
            plan=text(oauth, "subscriptionType"),
        )
        return Snapshot(
            kind=self.kind,
            secret=Sensitive(canonical(obj)),
            identity=identity,
            fingerprint=identity.fingerprint(self.kind),
            cred_hash=sha256_hex(canonical(credentials)),
            refresh_hash=sha256_hex(oauth["refreshToken"].encode()),
            access_expires_at=_ms(oauth.get("expiresAt")),
            refresh_expires_at=_ms(oauth.get("refreshTokenExpiresAt")),
            read=read,
        )

    # -- writing -----------------------------------------------------------

    def locks(self, timeout: float) -> contextlib.AbstractContextManager[Held]:
        """Claude's own locks, so no Claude process refreshes or writes meanwhile."""
        config_dir = self.paths.config_dir
        return hold_all(
            [
                DirLock(os.path.join(config_dir, ".oauth_refresh.lock"), stale_s=60),
                DirLock(os.path.realpath(config_dir) + ".lock", stale_s=60),
                DirLock(os.path.join(config_dir, ".storage-write.lock"), stale_s=15),
                DirLock(self.paths.identity_file + ".lock", stale_s=10),
            ],
            timeout,
            busy="Claude Code is refreshing or saving its login",
        )

    def install(self, secret: Sensitive, expect: Snapshot | None, held: Held) -> None:
        """Make ``secret`` the live login. Caller holds ``locks()``.

        ``expect`` is the live snapshot the caller decided on (None: logged
        out). If the store or config changed since, raises Conflict and
        writes nothing.
        """
        target = secret_object(self.parse_secret(secret).secret, self.kind)
        now = self._consistent_read()
        before: _Read | None = expect.read if expect is not None else None
        if expect is not None and before is None:
            raise ValueError("expect must be a live snapshot")
        if (now.store is None) != (before is None or before.store is None) or (
            now.store is not None
            and before is not None
            and before.store is not None
            and now.store.data != before.store.data
        ):
            raise StaleSnapshot("claude-changed", "Claude's login changed while switching")
        if before is not None and now.identity.version != before.identity.version:
            raise StaleSnapshot("claude-changed", "Claude's config changed while switching")

        blob = self._blob(now.store.data) if now.store is not None else {}
        merged = {k: blob[k] for k in MACHINE_KEYS if k in blob}
        merged.update(target["credentials"])
        self.store.write(json.dumps(merged, separators=(",", ":")).encode(), now.store)
        held.refresh()

        config = load_json_object(now.identity.data, self.paths.identity_file)
        config["oauthAccount"] = target["oauth_account"]
        write_foreign(
            self.paths.identity_file,
            json.dumps(config, indent=2, ensure_ascii=False).encode(),
            now.identity,
        )
        if self.on_macos:
            # A running session notices an outside login change by this file's
            # mtime, even with the login in the Keychain (design §3).
            touch(self.paths.credentials_file)
