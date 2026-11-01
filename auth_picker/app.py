"""Everything a command needs, built once per run."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass

from auth_picker import config, paths
from auth_picker.backends import KINDS, default_backends
from auth_picker.backends.base import Backend
from auth_picker.errors import ConfigError
from auth_picker.fsutil import read_private, remove_private, write_private
from auth_picker.journal import Journal, JournalStore
from auth_picker.profiles import Profiles
from auth_picker.secretstore import (
    SERVICE,
    KeychainStore,
    SecretStore,
    adopt_legacy,
    default_store,
)
from auth_picker.switch import Switcher, store_tag
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
    def load(
        cls, config_path: str | None = None, *, strict: bool = True, readonly: bool = False
    ) -> App:
        """Build the app.

        ``strict=False`` keeps going on a bad config (for status). ``readonly``
        creates and migrates nothing and spawns nothing (for the badge, which
        reads only the index, rescues and the usage cache).
        """
        error = None
        try:
            settings = config.load(config_path)
        except ConfigError as exc:
            if strict:
                raise
            settings, error = config.Config(), exc.message
        state = paths.state_dir()
        store = default_store(state, create=not readonly)
        backends = default_backends()
        profiles = Profiles(state, store, backends, settings.lock_timeout_s)
        journals = JournalStore(state, store)
        if not readonly:
            _adopt_legacy(state, store, profiles, journals, backends)
        switcher = Switcher(profiles, journals, lock_timeout=settings.lock_timeout_s)
        usage = Usage(state, settings.usage.ttl_s) if settings.usage.enabled else None
        return cls(settings, store, backends, profiles, journals, switcher, usage, error)


_ADOPTED = "keychain-per-install"


def _adopt_legacy(
    state: str,
    store: SecretStore,
    profiles: Profiles,
    journals: JournalStore,
    backends: dict[str, Backend],
    *,
    legacy: SecretStore | None = None,
) -> None:
    """Once per state dir, after upgrading from 1.0.0rc1.

    Move this install's items off the old shared Keychain service: profiles,
    undo, the pre-image of an interrupted switch and kept rescue logins. Move
    an interrupted switch's journal to its store's name, so recovery finds it.
    """
    marker = os.path.join(state, _ADOPTED)
    if not isinstance(store, KeychainStore) or os.path.exists(marker):
        return
    with profiles.locked():
        keys = [k for p in profiles.all() for k in (p.key, p.prev_key)]
        keys += [f"undo:{kind}" for kind in KINDS]
        keys += [entry["key"] for rescue in journals.rescues() for entry in rescue.kept]
        for kind in KINDS:
            old = os.path.join(journals.tx_dir, f"{kind}.json")
            data = read_private(old, 256 * 1024)
            if data is None:
                continue
            journal = Journal(**json.loads(data))
            journal.store = store_tag(backends[kind])
            keys.append(journal.pre_key)
            journals.write(journal)
            remove_private(old)
        adopt_legacy(store, legacy or KeychainStore(SERVICE, keychain=store.keychain), keys)
        write_private(marker, b"")
