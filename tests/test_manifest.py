"""The herdr manifest and the CLI must agree."""

from __future__ import annotations

import tomllib
from typing import Any

import pytest

from auth_picker import __version__
from auth_picker.cli import build_parser
from tests.conftest import ROOT


def _manifest() -> dict[str, Any]:
    with (ROOT / "herdr-plugin.toml").open("rb") as handle:
        return tomllib.load(handle)


def _commands() -> list[list[str]]:
    manifest = _manifest()
    entries = [
        *manifest.get("actions", []),
        *manifest.get("panes", []),
        *manifest.get("startup", []),
        *manifest.get("events", []),
    ]
    return [entry["command"] for entry in entries]


@pytest.mark.parametrize("command", _commands(), ids=lambda c: " ".join(c[2:]))
def test_every_manifest_command_is_isolated_and_parses(command: list[str]) -> None:
    assert command[:2] == ["/bin/sh", "bin/auth-picker"]
    build_parser().parse_args(command[2:])  # raises SystemExit if the CLI does not accept it


def test_versions_agree() -> None:
    with (ROOT / "pyproject.toml").open("rb") as handle:
        project_version = tomllib.load(handle)["project"]["version"]
    assert _manifest()["version"] == project_version == __version__
