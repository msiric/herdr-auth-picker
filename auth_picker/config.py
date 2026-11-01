"""Settings: one TOML file in the plugin's config directory.

Unknown keys and invalid values are errors, not silently ignored: a typo in a
safety setting must not quietly fall back to something else. ``status`` shows
the error, and other commands refuse to run until it is fixed.
"""

from __future__ import annotations

import os
import re
import tomllib
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from auth_picker import paths
from auth_picker.errors import ConfigError, UnsafePath
from auth_picker.fsutil import read_foreign

MAX_CONFIG_BYTES = 64 * 1024
BADGE_FIELDS = frozenset({"glyph", "label", "kind", "usage"})
_FIELD = re.compile(r"\{([^{}]*)\}")


@dataclass(frozen=True)
class UsageConfig:
    enabled: bool = False
    ttl_s: int = 300


@dataclass(frozen=True)
class Config:
    notify: bool = True
    notify_identity: bool = False
    badge: bool = True
    badge_format: str = "{glyph} {label}"
    glyph: str = "\N{BUST IN SILHOUETTE}"
    lock_timeout_s: float = 5.0
    usage: UsageConfig = field(default_factory=UsageConfig)


Validator = Callable[[Any], Any]


def _boolean(value: Any) -> bool:
    if not isinstance(value, bool):
        raise ValueError("must be true or false")
    return value


def _number(low: float, high: float, integer: bool = False) -> Validator:
    def check(value: Any) -> Any:
        if (
            isinstance(value, bool)
            or not isinstance(value, int | float)
            or (integer and not isinstance(value, int))
        ):
            raise ValueError("must be a whole number" if integer else "must be a number")
        if not low <= value <= high:
            raise ValueError(f"must be between {low:g} and {high:g}")
        return value

    return check


def _text(max_len: int) -> Validator:
    def check(value: Any) -> str:
        if not isinstance(value, str) or not value:
            raise ValueError("must be a non-empty string")
        if len(value) > max_len:
            raise ValueError(f"must be at most {max_len} characters")
        if any(unicodedata.category(c) == "Cc" for c in value):
            raise ValueError("must not contain control characters")
        return value

    return check


def _badge_format(value: Any) -> str:
    text: str = _text(64)(value)
    unknown = sorted(set(_FIELD.findall(text)) - BADGE_FIELDS)
    if unknown:
        raise ValueError(
            "may only use "
            + ", ".join(f"{{{f}}}" for f in sorted(BADGE_FIELDS))
            + f" (found {', '.join(f'{{{f}}}' for f in unknown)})"
        )
    return text


_TOP: dict[str, Validator] = {
    "notify": _boolean,
    "notify_identity": _boolean,
    "badge": _boolean,
    "badge_format": _badge_format,
    "glyph": _text(8),
    "lock_timeout_s": _number(0.5, 60),
}
_USAGE: dict[str, Validator] = {
    "enabled": _boolean,
    "ttl_s": _number(120, 86400, integer=True),
}


def _validate(
    table: dict[str, Any], specs: dict[str, Validator], prefix: str, problems: list[str]
) -> dict[str, Any]:
    values: dict[str, Any] = {}
    for key, value in table.items():
        name = prefix + key
        spec = specs.get(key)
        if spec is None:
            problems.append(f"unknown setting {name!r}")
            continue
        try:
            values[key] = spec(value)
        except ValueError as exc:
            problems.append(f"{name} {exc}")
    return values


def parse(raw: dict[str, Any], source: str = "config") -> Config:
    problems: list[str] = []
    top = dict(raw)
    usage_raw = top.pop("usage", {})
    if not isinstance(usage_raw, dict):
        problems.append("usage must be a table ([usage])")
        usage_raw = {}
    values = _validate(top, _TOP, "", problems)
    usage = _validate(usage_raw, _USAGE, "usage.", problems)
    if problems:
        raise ConfigError("config-invalid", f"{source}: " + "; ".join(problems))
    return Config(**values, usage=UsageConfig(**usage))


def default_path() -> str:
    return os.path.join(paths.config_dir(), "config.toml")


def load(path: str | None = None) -> Config:
    """The settings in ``path`` (default: the plugin config dir), or defaults if absent."""
    path = path or default_path()
    try:
        read = read_foreign(path, MAX_CONFIG_BYTES)
    except UnsafePath as exc:
        raise ConfigError("config-unsafe", exc.message) from None
    if read is None:
        return Config()
    try:
        raw = tomllib.loads(read.data.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError("config-parse", f"{path}: {exc}") from None
    return parse(raw, path)
