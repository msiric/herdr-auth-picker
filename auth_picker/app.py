"""Everything a command needs, built once per run."""

from __future__ import annotations

from dataclasses import dataclass

from auth_picker import config, paths
from auth_picker.backends import default_backends
from auth_picker.backends.base import Backend
from auth_picker.profiles import Profiles
from auth_picker.secretstore import SecretStore, default_store


@dataclass
class App:
    config: config.Config
    store: SecretStore
    backends: dict[str, Backend]
    profiles: Profiles

    @classmethod
    def load(cls, config_path: str | None = None) -> App:
        settings = config.load(config_path)
        store = default_store()
        backends = default_backends()
        profiles = Profiles(paths.state_dir(), store, backends, settings.lock_timeout_s)
        return cls(settings, store, backends, profiles)
