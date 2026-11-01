"""Everything a command needs, built once per run."""

from __future__ import annotations

from dataclasses import dataclass

from auth_picker import config, paths
from auth_picker.backends import default_backends
from auth_picker.backends.base import Backend
from auth_picker.errors import ConfigError
from auth_picker.journal import JournalStore
from auth_picker.profiles import Profiles
from auth_picker.secretstore import SecretStore, default_store
from auth_picker.switch import Switcher


@dataclass
class App:
    config: config.Config
    store: SecretStore
    backends: dict[str, Backend]
    profiles: Profiles
    journals: JournalStore
    switcher: Switcher
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
        store = default_store()
        backends = default_backends()
        state = paths.state_dir()
        profiles = Profiles(state, store, backends, settings.lock_timeout_s)
        journals = JournalStore(state, store)
        switcher = Switcher(profiles, journals, lock_timeout=settings.lock_timeout_s)
        return cls(settings, store, backends, profiles, journals, switcher, error)
