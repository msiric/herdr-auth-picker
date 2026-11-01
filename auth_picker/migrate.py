"""One-way import from the plugin this one replaces (rcosteira.account-switch).

The old plugin kept each login as a plaintext JSON file. This reads them,
checks each one, and saves the good ones as profiles here. It never changes
or deletes the old files; it lists them so you can delete them yourself.

A renewal the old plugin did not finish left its newest tokens in
``rotated/<kind>-<slug>.json``; the old plugin adopted that file on its next
run, and so does this import.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from typing import Any

from auth_picker import paths
from auth_picker.backends.base import Issue, Snapshot, canonical, validate
from auth_picker.backends.claude import ACCOUNT_KEYS, MACHINE_KEYS
from auth_picker.errors import AuthPickerError
from auth_picker.fsutil import read_foreign
from auth_picker.profiles import KINDS, Profile, ProfileError, Profiles, check_label
from auth_picker.redact import Sensitive

LEGACY_ID = "rcosteira.account-switch"
MAX_LEGACY_BYTES = 1024 * 1024


@dataclass
class Candidate:
    kind: str
    label: str
    source: str
    snapshot: Snapshot | None = None
    problem: str | None = None
    issues: list[Issue] = field(default_factory=list)

    @property
    def importable(self) -> bool:
        return self.snapshot is not None and self.problem is None


def default_legacy_dir() -> str:
    return os.path.join(os.path.dirname(paths.state_dir()), LEGACY_ID)


def _load(path: str) -> dict[str, Any] | None:
    found = read_foreign(path, MAX_LEGACY_BYTES)
    if found is None:
        return None
    data = json.loads(found.data)
    return data if isinstance(data, dict) else None


def _secret(kind: str, payload: dict[str, Any]) -> dict[str, Any]:
    if kind == "codex":
        auth = payload.get("auth")
        if not isinstance(auth, dict):
            raise ValueError("no Codex login in it")
        return {"schema": 1, "kind": kind, "auth": auth}
    blob = payload.get("credentials")
    if isinstance(blob, str):
        blob = json.loads(blob)
    if not isinstance(blob, dict):
        raise ValueError("no Claude credential in it")
    unknown = sorted(set(blob) - set(ACCOUNT_KEYS) - set(MACHINE_KEYS))
    if unknown:
        raise ValueError("unknown credential keys: " + ", ".join(unknown))
    account = payload.get("oauth_account")
    if not isinstance(account, dict):
        raise ValueError("no account identity saved with it")
    credentials = {k: blob[k] for k in ACCOUNT_KEYS if k in blob}
    return {"schema": 1, "kind": kind, "credentials": credentials, "oauth_account": account}


def plan(legacy_dir: str, profiles: Profiles, now: float | None = None) -> list[Candidate]:
    """What an import would do, without doing it."""
    now = time.time() if now is None else now
    out: list[Candidate] = []
    for kind in KINDS:
        directory = os.path.join(legacy_dir, "profiles", kind)
        try:
            names = sorted(n for n in os.listdir(directory) if n.endswith(".json"))
        except FileNotFoundError:
            continue
        for name in names:
            source = os.path.join(directory, name)
            candidate = Candidate(kind, name[:-5], source)
            out.append(candidate)
            try:
                data = _load(source)
                if data is None or not isinstance(data.get("payload"), dict):
                    raise ValueError("not a saved login")
                candidate.label = check_label(str(data.get("label") or name[:-5]))
                slug = str(data.get("slug") or name[:-5])
                staged = _load(os.path.join(legacy_dir, "rotated", f"{kind}-{slug}.json"))
                payload = staged if staged else data["payload"]
                secret = Sensitive(canonical(_secret(kind, payload)))
                candidate.snapshot = profiles.backends[kind].parse_secret(secret)
            except (ValueError, KeyError, TypeError, AuthPickerError) as exc:
                message = exc.message if isinstance(exc, AuthPickerError) else str(exc)
                candidate.problem = f"skipped: {message}"
                continue
            existing = profiles.by_fingerprint(kind, candidate.snapshot.fingerprint)
            if existing is not None:
                candidate.problem = f"skipped: already saved as {existing.label}"
                continue
            candidate.issues = validate(candidate.snapshot, now)
            if any(issue.hard for issue in candidate.issues):
                candidate.problem = "skipped: " + "; ".join(i.message for i in candidate.issues)
    return out


def apply(candidates: list[Candidate], profiles: Profiles) -> list[Profile]:
    imported: list[Profile] = []
    for candidate in candidates:
        if not candidate.importable or candidate.snapshot is None:
            continue
        for label in (candidate.label, f"{candidate.label} (imported)"):
            try:
                imported.append(profiles.create(label, candidate.snapshot))
                break
            except ProfileError as exc:
                if exc.code != "label-taken":
                    candidate.problem = f"skipped: {exc.message}"
                    break
        else:
            candidate.problem = "skipped: its name is taken"
    return imported


def leftovers(legacy_dir: str) -> list[str]:
    """The old plugin's directories that hold plaintext secrets."""
    names = ("profiles", "backups", "rotated")
    return [p for p in (os.path.join(legacy_dir, n) for n in names) if os.path.isdir(p)]
