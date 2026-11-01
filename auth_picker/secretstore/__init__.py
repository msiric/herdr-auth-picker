"""Where profile secrets live at rest.

macOS: one generic-password item per key in the login keychain.
Elsewhere: one 0600 file per key in a 0700 directory.
"""

from __future__ import annotations

import os
import platform

from auth_picker import paths
from auth_picker.secretstore.base import SERVICE, SecretStore, check_key
from auth_picker.secretstore.filestore import FileStore
from auth_picker.secretstore.keychain import KeychainStore

__all__ = ["SERVICE", "FileStore", "KeychainStore", "SecretStore", "check_key", "default_store"]


def default_store() -> SecretStore:
    if platform.system() == "Darwin":
        return KeychainStore(SERVICE)
    return FileStore(os.path.join(paths.state_dir(), "secrets"))
