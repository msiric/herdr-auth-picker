"""Where profile secrets live at rest.

macOS: generic-password items in the login keychain, under a service of their
own per state directory (``msiric.auth-picker.<install id>``), so two
installs, or a terminal with a different state dir, never see or clean up
each other's secrets. Elsewhere: 0600 files in ``<state dir>/secrets``.
"""

from __future__ import annotations

import os
import platform
import re
import uuid

from auth_picker.fsutil import read_private, secure_dir, write_private
from auth_picker.secretstore.base import SERVICE, SecretStore, check_key
from auth_picker.secretstore.filestore import FileStore
from auth_picker.secretstore.keychain import KeychainStore

__all__ = [
    "SERVICE",
    "FileStore",
    "KeychainStore",
    "SecretStore",
    "adopt_legacy",
    "check_key",
    "default_store",
    "install_id",
]

_ID = re.compile(r"[0-9a-f]{16}")


def install_id(state_dir: str) -> str:
    """A random id for this state directory, made once and kept."""
    path = os.path.join(state_dir, "install-id")
    data = read_private(path, 64)
    if data is not None and _ID.fullmatch(data.decode("ascii", "replace").strip()):
        return data.decode().strip()
    secure_dir(state_dir)
    new = uuid.uuid4().hex[:16]
    write_private(path, new.encode())
    return new


def default_store(state_dir: str) -> SecretStore:
    if platform.system() == "Darwin":
        return KeychainStore(f"{SERVICE}.{install_id(state_dir)}")
    return FileStore(os.path.join(state_dir, "secrets"))


def adopt_legacy(store: SecretStore, legacy: SecretStore, keys: list[str]) -> list[str]:
    """Move ``keys`` from the shared service used up to 1.0.0rc1 into ``store``.

    Only keys this install's index names are moved; anything else under the
    old service is left alone, since it may belong to another install.
    """
    moved = []
    for key in keys:
        value = legacy.get(key)
        if value is None:
            continue
        if store.get(key) is None:
            store.put(key, value)  # put() reads back and compares
        legacy.delete(key)
        moved.append(key)
    return moved
