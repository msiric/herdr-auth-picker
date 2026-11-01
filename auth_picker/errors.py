"""Typed, user-facing errors.

A message is built from labels, kinds and codes only. Never put a credential,
a token, a raw file body or a subprocess's output in one: messages reach
stderr, which herdr keeps in its plugin logs.
"""

from __future__ import annotations


class AuthPickerError(Exception):
    """An expected failure, reported to the user as one line."""

    exit_code = 1

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class ConfigError(AuthPickerError):
    """The plugin's config file is unreadable or invalid."""


class LockTimeout(AuthPickerError):
    """Another operation held a lock for longer than we wait."""


class UnsafePath(AuthPickerError):
    """A path is a symlink, owned by someone else, or writable by others."""


class Conflict(AuthPickerError):
    """A file changed between our read and our write."""


class StaleSnapshot(Conflict):
    """The login moved since it was read, and nothing at all was written."""


class ProcessFailed(AuthPickerError):
    """A command timed out, produced too much output, or could not start."""
