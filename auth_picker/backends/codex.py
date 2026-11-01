"""Codex's login: ``$CODEX_HOME/auth.json`` in file mode.

Codex 0.163.0 rewrites auth.json in place with no lock, so a read can see a
half-written file: a parse failure means "being written", never "logged out".
Newer Codex takes an flock on ``auth.json.lock``; we take it too (design §3).
"""

from __future__ import annotations

import contextlib
import json
import os
import time
import tomllib
from typing import Any

from auth_picker.backends.base import (
    SCHEMA,
    Identity,
    Inconsistent,
    Snapshot,
    Unsupported,
    canonical,
    jwt_claims,
    load_json_object,
    secret_object,
    sha256_hex,
    text,
)
from auth_picker.errors import Conflict
from auth_picker.foreignlock import Flock, Held, hold_all
from auth_picker.fsutil import ForeignFile, read_foreign, write_foreign
from auth_picker.redact import Sensitive

MAX_AUTH_BYTES = 1024 * 1024
MAX_CONFIG_BYTES = 4 * 1024 * 1024
_AUTH_CLAIMS = "https://api.openai.com/auth"
_PROFILE_CLAIMS = "https://api.openai.com/profile"
_READ_ATTEMPTS = 5


def codex_home(env: dict[str, str] | None = None) -> str:
    env = dict(os.environ) if env is None else env
    home = env.get("HOME") or os.path.expanduser("~")
    return env.get("CODEX_HOME") or os.path.join(home, ".codex")


class CodexBackend:
    kind = "codex"
    title = "Codex"

    def __init__(self, home: str) -> None:
        self.home = home
        self.auth_file = os.path.join(home, "auth.json")

    def check_supported(self) -> None:
        if not os.path.isdir(self.home):
            raise Unsupported("codex-absent", "Codex is not set up on this machine")
        config = read_foreign(os.path.join(self.home, "config.toml"), MAX_CONFIG_BYTES)
        if config is None:
            return
        try:
            mode = tomllib.loads(config.data.decode("utf-8")).get("cli_auth_credentials_store")
        except (UnicodeDecodeError, tomllib.TOMLDecodeError):
            raise Unsupported("codex-config", "Codex's config.toml does not parse") from None
        if mode not in (None, "file"):
            raise Unsupported(
                "codex-store",
                f'Codex stores logins in "{mode}" mode; only "file" mode is supported',
            )

    def _consistent_read(self) -> ForeignFile | None:
        for _ in range(_READ_ATTEMPTS):
            first = read_foreign(self.auth_file, MAX_AUTH_BYTES)
            if first is None:
                return None
            with contextlib.suppress(Inconsistent):
                load_json_object(first.data, "auth.json")
                second = read_foreign(self.auth_file, MAX_AUTH_BYTES)
                if second is not None and second.version == first.version:
                    return first
            time.sleep(0.05)
        raise Inconsistent("codex-changing", "Codex's auth.json is being written; try again")

    def read_live(self) -> Snapshot | None:
        found = self._consistent_read()
        if found is None:
            return None
        auth = load_json_object(found.data, "auth.json")
        return self._snapshot({"schema": SCHEMA, "kind": self.kind, "auth": auth}, found)

    def parse_secret(self, secret: Sensitive) -> Snapshot:
        return self._snapshot(secret_object(secret, self.kind), None)

    def _snapshot(self, obj: dict[str, Any], read: ForeignFile | None) -> Snapshot:
        auth = obj.get("auth")
        tokens = auth.get("tokens") if isinstance(auth, dict) else None
        if not isinstance(tokens, dict) or not all(
            text(tokens, k) for k in ("id_token", "access_token", "refresh_token")
        ):
            raise Unsupported(
                "codex-login-kind", "only ChatGPT logins are supported (no tokens in auth.json)"
            )
        claims = jwt_claims(tokens["id_token"])
        auth_claims = claims.get(_AUTH_CLAIMS)
        auth_claims = auth_claims if isinstance(auth_claims, dict) else {}
        account_id = text(auth_claims, "chatgpt_account_id")
        if account_id is None:
            raise Inconsistent("codex-no-identity", "Codex's id_token names no account")
        stored = text(tokens, "account_id")
        if stored is not None and stored != account_id:
            raise Inconsistent("codex-mismatch", "Codex's auth.json names two different accounts")
        profile = claims.get(_PROFILE_CLAIMS)
        email = text(claims, "email") or (
            text(profile, "email") if isinstance(profile, dict) else None
        )
        identity = Identity(
            account_id=account_id,
            subject_id=text(auth_claims, "chatgpt_user_id")
            or text(auth_claims, "user_id")
            or text(claims, "sub"),
            email=email,
            plan=text(auth_claims, "chatgpt_plan_type"),
        )
        expires = jwt_claims(tokens["access_token"]).get("exp")
        return Snapshot(
            kind=self.kind,
            secret=Sensitive(canonical(obj)),
            identity=identity,
            fingerprint=identity.fingerprint(self.kind),
            cred_hash=sha256_hex(canonical(tokens)),
            refresh_hash=sha256_hex(tokens["refresh_token"].encode()),
            access_expires_at=float(expires) if isinstance(expires, int | float) else None,
            refresh_expires_at=None,
            read=read,
        )

    def locks(self, timeout: float) -> contextlib.AbstractContextManager[Held]:
        return hold_all(
            [Flock(os.path.realpath(self.auth_file) + ".lock")],
            timeout,
            busy="Codex is saving its login",
        )

    def install(self, secret: Sensitive, expect: Snapshot | None, held: Held) -> None:
        """Make ``secret`` the live login. Caller holds ``locks()``.

        Raises Conflict, writing nothing, if auth.json is no longer what
        ``expect`` read (None: logged out).
        """
        target = secret_object(self.parse_secret(secret).secret, self.kind)
        now = self._consistent_read()
        before: ForeignFile | None = expect.read if expect is not None else None
        if expect is not None and before is None:
            raise ValueError("expect must be a live snapshot")
        if (now is None) != (before is None) or (
            now is not None and before is not None and now.version != before.version
        ):
            raise Conflict("codex-changed", "Codex's login changed while switching")
        held.refresh()
        write_foreign(
            self.auth_file,
            (json.dumps(target["auth"], indent=2, ensure_ascii=False) + "\n").encode(),
            now,
            new_mode=0o600,
        )
