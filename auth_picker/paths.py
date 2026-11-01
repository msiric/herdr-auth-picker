"""Where things live.

herdr hands plugin commands their state and config directories. A command run
from a tab bar or a status line gets no herdr environment, so the defaults
match the directories herdr creates (observed on herdr 0.9.1).
"""

from __future__ import annotations

import hashlib
import os

from auth_picker.errors import UnsafePath

PLUGIN_ID = "msiric.auth-picker"


def _xdg(var: str, fallback: str) -> str:
    value = os.environ.get(var, "")
    return value if os.path.isabs(value) else os.path.expanduser(fallback)


def _from_env(var: str, default: str) -> str:
    value = os.environ.get(var)
    if not value:
        return default
    if not os.path.isabs(value):
        raise UnsafePath("relative-path", f"{var} must be an absolute path")
    return value


def state_dir() -> str:
    default = os.path.join(_xdg("XDG_STATE_HOME", "~/.local/state"), "herdr", "plugins", PLUGIN_ID)
    return _from_env("HERDR_PLUGIN_STATE_DIR", default)


def config_dir() -> str:
    default = os.path.join(
        _xdg("XDG_CONFIG_HOME", "~/.config"), "herdr", "plugins", "config", PLUGIN_ID
    )
    return _from_env("HERDR_PLUGIN_CONFIG_DIR", default)


def store_lock_path(store_identity: str) -> str:
    """The machine-wide lock for one credential store.

    Outside any herdr state directory, so every install, session and tab-bar
    command of this plugin agrees on it (design §4).
    """
    digest = hashlib.sha256(store_identity.encode()).hexdigest()[:32]
    base = _xdg("XDG_STATE_HOME", "~/.local/state")
    return os.path.join(base, PLUGIN_ID, "locks", f"{digest}.lock")
