"""Everything a command needs, built once per run."""

from __future__ import annotations

import os
from dataclasses import dataclass

from auth_picker import config, paths
from auth_picker.backends import KINDS, default_backends
from auth_picker.backends.base import Backend
from auth_picker.errors import ConfigError
from auth_picker.fsutil import write_private
from auth_picker.journal import JournalStore
from auth_picker.profiles import Profiles
from auth_picker.secretstore import (
    SERVICE,
    KeychainStore,
    SecretStore,
    adopt_legacy,
    default_store,
)
from auth_picker.switch import Switcher
from auth_picker.usage import Usage


@dataclass
class App:
    config: config.Config
    store: SecretStore
    backends: dict[str, Backend]
    profiles: Profiles
    journals: JournalStore
    switcher: Switcher
    usage: Usage | None = None
    config_error: str | None = None

    @classmethod
    def load(cls, config_path: str | None = None, *, strict: bool = True) -> App:
        """Build the app. ``strict=False`` keeps going on a bad config (for status)."""
        error = None
        try:
            settings = config.load(config_path)
        except ConfigError as exc:
            if strict:
                raise
            settings, error = config.Config(), exc.message
        state = paths.state_dir()
        store = default_store(state)
        backends = default_backends()
        profiles = Profiles(state, store, backends, settings.lock_timeout_s)
        _adopt_legacy_keychain(state, store, profiles)
        journals = JournalStore(state, store)
        switcher = Switcher(profiles, journals, lock_timeout=settings.lock_timeout_s)
        usage = Usage(state, settings.usage.ttl_s) if settings.usage.enabled else None
        return cls(settings, store, backends, profiles, journals, switcher, usage, error)


_ADOPTED = "keychain-per-install"


def _adopt_legacy_keychain(state: str, store: SecretStore, profiles: Profiles) -> None:
    """Once per state dir: move this install's items off the old shared service."""
    marker = os.path.join(state, _ADOPTED)
    if not isinstance(store, KeychainStore) or os.path.exists(marker):
        return
    keys = [k for p in profiles.all() for k in (p.key, p.prev_key)]
    keys += [f"undo:{kind}" for kind in KINDS]
    with profiles.locked():
        adopt_legacy(store, KeychainStore(SERVICE), keys)
        write_private(marker, b"")
