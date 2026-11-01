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

from auth_picker.errors import AuthPickerError
from auth_picker.fsutil import create_private, read_private
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
    "existing_install_id",
    "install_id",
]

_ID = re.compile(r"[0-9a-f]{16}")


def existing_install_id(state_dir: str) -> str | None:
    data = read_private(os.path.join(state_dir, "install-id"), 64)
    text = data.decode("ascii", "replace").strip() if data is not None else ""
    return text if _ID.fullmatch(text) else None


def install_id(state_dir: str) -> str:
    """A random id for this state directory, made once and kept.

    Two processes starting at once must agree: the file is only ever created
    if absent, and whoever loses reads the winner's id.
    """
    found = existing_install_id(state_dir)
    if found is not None:
        return found
    create_private(os.path.join(state_dir, "install-id"), uuid.uuid4().hex[:16].encode())
    found = existing_install_id(state_dir)
    if found is None:
        raise ValueError(f"{state_dir}/install-id is damaged; move it aside")
    return found


def default_store(state_dir: str, *, create: bool = True) -> SecretStore:
    """The store for this state dir. ``create=False`` never writes (for the badge)."""
    if platform.system() == "Darwin":
        ident = install_id(state_dir) if create else existing_install_id(state_dir)
        return KeychainStore(f"{SERVICE}.{ident or 'unset'}")
    return FileStore(os.path.join(state_dir, "secrets"))


def adopt_legacy(
    store: SecretStore, legacy: SecretStore, keys: list[str]
) -> tuple[list[str], list[str]]:
    """Move ``keys`` from the shared service used up to 1.0.0rc1 into ``store``.

    Only keys this install's state names are moved; anything else under the
    old service is left alone, since it may belong to another install. A key
    that cannot be moved (locked keychain, damaged item) is skipped and
    returned in the second list, to be tried again later. Returns (moved, failed).
    """
    moved: list[str] = []
    failed: list[str] = []
    for key in keys:
        try:
            value = legacy.get(key)
            if value is None:
                continue
            if store.get(key) is None:
                store.put(key, value)  # put() reads back and compares
            legacy.delete(key)
        except AuthPickerError:
            failed.append(key)
            continue
        moved.append(key)
    return moved, failed
