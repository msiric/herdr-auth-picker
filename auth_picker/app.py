"""Everything a command needs, built once per run."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

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
    # Items the upgrade from 1.0.0rc1 could not move yet (shown by status).
    unmoved: list[str] = field(default_factory=list)

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
        unmoved = [] if readonly else _adopt_legacy(state, store, profiles, journals, backends)
        switcher = Switcher(profiles, journals, lock_timeout=settings.lock_timeout_s)
        usage = Usage(state, settings.usage.ttl_s) if settings.usage.enabled else None
        return cls(settings, store, backends, profiles, journals, switcher, usage, error, unmoved)


_ADOPTED = "keychain-per-install"


def _adopt_legacy(
    state: str,
    store: SecretStore,
    profiles: Profiles,
    journals: JournalStore,
    backends: dict[str, Backend],
    *,
    legacy: SecretStore | None = None,
) -> list[str]:
    """Once per state dir, after upgrading from 1.0.0rc1. Returns keys not yet moved.

    Move this install's items off the old shared Keychain service: profiles,
    undo, every journal's pre-image and every kept rescue login. Only then is
    an old-style journal renamed for its store, so a failure part-way never
    loses track of a pre-image. Nothing here stops a command: what could not
    move is reported, and tried again next time; the marker is written only
    once everything has moved.
    """
    marker = os.path.join(state, _ADOPTED)
    if not isinstance(store, KeychainStore) or os.path.exists(marker):
        return []
    with profiles.locked():
        keys = [k for p in profiles.all() for k in (p.key, p.prev_key)]
        keys += [f"undo:{kind}" for kind in KINDS]
        keys += [entry["key"] for rescue in journals.rescues() for entry in rescue.kept]
        old_style: list[tuple[str, Journal]] = []
        names = sorted(os.listdir(journals.tx_dir)) if os.path.isdir(journals.tx_dir) else []
        for name in names:
            data = read_private(os.path.join(journals.tx_dir, name), 256 * 1024)
            if data is None or not name.endswith(".json"):
                continue
            journal = Journal(**json.loads(data))
            keys.append(journal.pre_key)
            if name == f"{journal.kind}.json":
                old_style.append((name, journal))
        _moved, failed = adopt_legacy(
            store, legacy or KeychainStore(SERVICE, keychain=store.keychain), keys
        )
        for name, journal in old_style:
            if journal.pre_key in failed:
                continue
            journal.store = store_tag(backends[journal.kind])
            journals.write(journal)
            remove_private(os.path.join(journals.tx_dir, name))
        if not failed:
            write_private(marker, b"")
        return failed
