"""Talking to herdr through its CLI. Every call fails soft: herdr may be absent."""

from __future__ import annotations

import json
import os
import shutil
from typing import Any

from auth_picker import paths, proc
from auth_picker.errors import ProcessFailed

BADGE_FIELD = "acct"
USAGE_FIELD = "usage"
TIMEOUT_S = 10.0


def binary() -> str | None:
    given = os.environ.get("HERDR_BIN_PATH", "")
    if os.path.isabs(given) and os.access(given, os.X_OK):
        return given
    found = shutil.which("herdr")
    return os.path.realpath(found) if found else None


def invoked_by_herdr() -> bool:
    return os.environ.get("HERDR_PLUGIN_ID") == paths.PLUGIN_ID


def _run(*args: str) -> proc.Result | None:
    program = binary()
    if program is None:
        return None
    try:
        return proc.run([program, *args], timeout=TIMEOUT_S)
    except ProcessFailed:
        return None


def agents() -> list[dict[str, Any]]:
    result = _run("agent", "list")
    if result is None or not result.ok:
        return []
    try:
        listed = json.loads(result.stdout)["result"]["agents"]
    except (ValueError, KeyError, TypeError):
        return []
    return [a for a in listed if isinstance(a, dict) and isinstance(a.get("pane_id"), str)]


def kind_of_agent(agent: dict[str, Any]) -> str | None:
    label = " ".join(str(agent.get(k) or "") for k in ("agent", "name", "display_agent")).lower()
    return next((kind for kind in ("claude", "codex") if kind in label), None)


def focused_kind() -> str | None:
    """The agent kind of the pane herdr says is focused, if it is one we handle."""
    try:
        context = json.loads(os.environ.get("HERDR_PLUGIN_CONTEXT_JSON") or "{}")
    except ValueError:
        return None
    agent = context.get("focused_pane_agent") if isinstance(context, dict) else None
    return kind_of_agent({"agent": agent}) if isinstance(agent, str) else None


def report(pane_id: str, tokens: dict[str, str], clear: tuple[str, ...] = ()) -> None:
    """Set and clear this plugin's tokens on one pane, in one herdr call."""
    args = ["pane", "report-metadata", pane_id, "--source", paths.PLUGIN_ID]
    for name, value in tokens.items():
        args += ["--token", f"{name}={value}"]
    for name in clear:
        args += ["--clear-token", name]
    if tokens or clear:
        _run(*args)


def stamp_soon() -> bool:
    """Have herdr refresh the badges in the background (the `stamp` action).

    herdr runs and tracks it, so nothing outlives us and nobody waits for it.
    """
    result = _run("plugin", "action", "invoke", f"{paths.PLUGIN_ID}.stamp")
    return result is not None and result.ok


def event() -> dict[str, str]:
    """The event a hook was started for: {"pane_id", "agent", "agent_status", ...}."""
    try:
        raw = json.loads(os.environ.get("HERDR_PLUGIN_EVENT_JSON") or "{}")
    except ValueError:
        return {}
    data = raw.get("data") if isinstance(raw, dict) else None
    if not isinstance(data, dict):
        return {}
    return {k: v for k, v in data.items() if isinstance(v, str)}


def notify(title: str, body: str = "") -> None:
    args = ["notification", "show", title, "--sound", "none"]
    if body:
        args += ["--body", body]
    _run(*args)


def open_pane(entrypoint: str) -> bool:
    result = _run(
        "plugin",
        "pane",
        "open",
        "--plugin",
        paths.PLUGIN_ID,
        "--entrypoint",
        entrypoint,
        "--placement",
        "overlay",
    )
    return result is not None and result.ok
