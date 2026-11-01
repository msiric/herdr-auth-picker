from __future__ import annotations

import json
from pathlib import Path

import pytest

from auth_picker import herdr

FAKE = """#!/bin/sh
printf '%s\\n' "$*" >> "{log}"
if [ "$1" = agent ]; then
  printf '%s' '{agents}'
fi
"""


@pytest.fixture
def real_herdr_binary(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A stand-in herdr that records its arguments."""
    log = tmp_path / "calls"
    agents = json.dumps(
        {
            "result": {
                "agents": [
                    {"pane_id": "p1", "agent": "claude"},
                    {"pane_id": "p2", "agent": "copilot"},
                ]
            }
        }
    )
    script = tmp_path / "herdr"
    script.write_text(FAKE.format(log=log, agents=agents))
    script.chmod(0o755)
    monkeypatch.setenv("HERDR_BIN_PATH", str(script))
    return log


def test_calls_go_to_herdr_with_plain_argv(real_herdr_binary: Path) -> None:
    herdr.set_badge("p1", "👤 work")
    herdr.notify("Claude Code: work", "switched")
    assert herdr.agents()[0]["pane_id"] == "p1"
    calls = real_herdr_binary.read_text().splitlines()
    assert calls[0] == "pane report-metadata p1 --source msiric.auth-picker --token acct=👤 work"
    assert calls[1] == "notification show Claude Code: work --sound none --body switched"


@pytest.mark.parametrize(
    ("context", "kind"),
    [
        ('{"focused_pane_agent": "claude"}', "claude"),
        ('{"focused_pane_agent": "copilot"}', None),
        ("not json", None),
        ("", None),
    ],
)
def test_focused_kind(monkeypatch: pytest.MonkeyPatch, context: str, kind: str | None) -> None:
    monkeypatch.setenv("HERDR_PLUGIN_CONTEXT_JSON", context)
    assert herdr.focused_kind() == kind


def test_without_herdr_everything_is_a_quiet_no_op() -> None:
    assert herdr.agents() == []
    herdr.notify("x")
