from __future__ import annotations

import argparse

import pytest

from auth_picker import cli
from auth_picker.errors import AuthPickerError

TOKEN = "sk-ant-oat01-ShouldNeverBePrinted0123456789"


def _status_raises(monkeypatch: pytest.MonkeyPatch, exc: BaseException) -> None:
    def handler(_args: argparse.Namespace) -> int:
        raise exc

    monkeypatch.setattr(cli, "_cmd_status", handler)


def test_expected_errors_print_one_redacted_line(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _status_raises(monkeypatch, AuthPickerError("x", f"refused {TOKEN}"))
    assert cli.main(["status"]) == 1
    stderr = capsys.readouterr().err
    assert stderr.startswith("auth-picker: refused")
    assert TOKEN not in stderr


def test_internal_errors_hide_details_by_default(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _status_raises(monkeypatch, KeyError(TOKEN))
    assert cli.main(["status"]) == cli.EXIT_INTERNAL
    stderr = capsys.readouterr().err
    assert "internal error (KeyError)" in stderr
    assert "sk-ant" not in stderr


def test_debug_traceback_is_still_redacted(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _status_raises(monkeypatch, KeyError(TOKEN))
    assert cli.main(["--debug", "status"]) == cli.EXIT_INTERNAL
    stderr = capsys.readouterr().err
    assert "Traceback" in stderr
    assert TOKEN not in stderr
