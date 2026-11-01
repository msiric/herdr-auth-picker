from __future__ import annotations

from pathlib import Path

import pytest

from auth_picker.config import Config, UsageConfig, load
from auth_picker.errors import ConfigError


def _write(tmp_path: Path, text: str) -> str:
    path = tmp_path / "config.toml"
    path.write_text(text, encoding="utf-8")
    return str(path)


def test_missing_file_means_defaults(tmp_path: Path) -> None:
    assert load(str(tmp_path / "config.toml")) == Config()


def test_valid_file(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        'glyph = "🔑"\nbadge_format = "{kind}: {label}"\nnotify = false\n'
        "lock_timeout_s = 2.5\n[usage]\nenabled = true\nttl_s = 600\n",
    )
    assert load(path) == Config(
        glyph="🔑",
        badge_format="{kind}: {label}",
        notify=False,
        lock_timeout_s=2.5,
        usage=UsageConfig(enabled=True, ttl_s=600),
    )


@pytest.mark.parametrize(
    ("text", "complaint"),
    [
        ("verify_switch = false\n", "unknown setting 'verify_switch'"),
        ('notify = "false"\n', "notify must be true or false"),
        ("lock_timeout_s = true\n", "lock_timeout_s must be a number"),
        ("lock_timeout_s = 600\n", "lock_timeout_s must be between"),
        ("[usage]\nttl_s = 30\n", "usage.ttl_s must be between"),
        ('badge_format = "{name.__class__}"\n', "badge_format may only use"),
        ('glyph = "\\u001b[31m"\n', "glyph must not contain control characters"),
        ('usage = "on"\n', "usage must be a table"),
        ('codex_restart = "sometimes"\n', "codex_restart must be one of"),
    ],
)
def test_invalid_settings_are_errors(tmp_path: Path, text: str, complaint: str) -> None:
    with pytest.raises(ConfigError, match="config") as caught:
        load(_write(tmp_path, text))
    assert complaint in caught.value.message


def test_every_problem_is_reported_at_once(tmp_path: Path) -> None:
    with pytest.raises(ConfigError) as caught:
        load(_write(tmp_path, 'notify = 1\nbadge = "yes"\n'))
    assert "notify" in caught.value.message
    assert "badge" in caught.value.message


def test_unparseable_file_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        load(_write(tmp_path, "notify = \n"))


def test_symlinked_config_is_followed(tmp_path: Path) -> None:
    real = tmp_path / "dotfiles.toml"
    real.write_text("notify = false\n")
    link = tmp_path / "config.toml"
    link.symlink_to(real)
    assert load(str(link)).notify is False
