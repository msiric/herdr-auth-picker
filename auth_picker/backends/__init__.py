"""Credential backends, one per supported CLI."""

from __future__ import annotations

from auth_picker.backends.base import Backend
from auth_picker.backends.claude import ClaudeBackend, resolve_paths
from auth_picker.backends.codex import CodexBackend, codex_home

KINDS = ("claude", "codex")


def default_backends() -> dict[str, Backend]:
    return {
        "claude": ClaudeBackend(resolve_paths()),
        "codex": CodexBackend(codex_home()),
    }
