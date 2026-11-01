"""Shared pieces of the secret stores: the key alphabet and the interface."""

from __future__ import annotations

import re
from typing import Protocol

from auth_picker.redact import Sensitive

SERVICE = "msiric.auth-picker"
_KEY = re.compile(r"[a-z]+(?::[A-Za-z0-9._-]{1,64}){1,3}")


def check_key(key: str) -> str:
    """Keys end up in a ``security -i`` command line and in file names."""
    if not _KEY.fullmatch(key):
        raise ValueError(f"invalid secret key {key!r}")
    return key


class SecretStore(Protocol):
    def get(self, key: str) -> Sensitive | None: ...
    def put(self, key: str, value: Sensitive) -> None: ...
    def delete(self, key: str) -> bool: ...
    def keys(self) -> list[str]: ...
