"""Secrets as 0600 files in a 0700 directory (Linux, and tests)."""

from __future__ import annotations

import os

from auth_picker.fsutil import read_private, remove_private, secure_dir, write_private
from auth_picker.redact import Sensitive
from auth_picker.secretstore.base import check_key

MAX_SECRET_BYTES = 1024 * 1024
_SUFFIX = ".secret"


class FileStore:
    def __init__(self, directory: str) -> None:
        self.directory = directory

    def _path(self, key: str) -> str:
        return os.path.join(self.directory, check_key(key) + _SUFFIX)

    def get(self, key: str) -> Sensitive | None:
        data = read_private(self._path(key), MAX_SECRET_BYTES)
        return Sensitive(data) if data is not None else None

    def put(self, key: str, value: Sensitive) -> None:
        secure_dir(self.directory)
        write_private(self._path(key), value.reveal())

    def delete(self, key: str) -> bool:
        path = self._path(key)
        existed = os.path.lexists(path)
        remove_private(path)
        return existed

    def keys(self) -> list[str]:
        try:
            names = os.listdir(self.directory)
        except FileNotFoundError:
            return []
        return sorted(n[: -len(_SUFFIX)] for n in names if n.endswith(_SUFFIX))
