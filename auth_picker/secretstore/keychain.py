"""Secrets as generic-password items in a macOS keychain, via /usr/bin/security.

Writes go through ``security -i`` with the command on stdin and the value as
``-X <hex>``. The value never appears in any process's argv, and no quoting
can go wrong. Do not use ``add-generic-password -w`` with a piped stdin: it
fails its retype prompt, exits 0, and stores an EMPTY password (verified on
macOS 26.7.1; this is how the original plugin blanked logins).

Our own items hold base64 text, so ``find-generic-password -w`` always prints
them verbatim (``security`` switches to hex for non-printable data).

Every item is in the login keychain unless ``keychain`` names another file;
tests use a throwaway keychain file and never touch the login keychain.
"""

from __future__ import annotations

import base64
import binascii
import re

from auth_picker import proc
from auth_picker.errors import AuthPickerError
from auth_picker.redact import Sensitive
from auth_picker.secretstore.base import check_key

SECURITY = "/usr/bin/security"
ITEM_NOT_FOUND = 44  # errSecItemNotFound, as security(1) reports it
_LABEL = "auth-picker saved login"
_SERVICE = re.compile(r"[A-Za-z0-9._-]{1,128}")


class KeychainError(AuthPickerError):
    """The keychain refused a read or write (locked, denied, unavailable)."""


class KeychainStore:
    def __init__(self, service: str, keychain: str | None = None) -> None:
        if not _SERVICE.fullmatch(service):
            raise ValueError(f"invalid keychain service {service!r}")
        self.service = service
        self.keychain = keychain

    def _target(self) -> list[str]:
        return [self.keychain] if self.keychain else []

    def get(self, key: str) -> Sensitive | None:
        raw = read_password(self.service, check_key(key), self.keychain)
        if raw is None:
            return None
        try:
            return Sensitive(base64.b64decode(raw.reveal().strip(), validate=True))
        except binascii.Error:
            raise KeychainError(
                "keychain-format", f"keychain item {key} is not in the expected format"
            ) from None

    def put(self, key: str, value: Sensitive) -> None:
        encoded = Sensitive(base64.b64encode(value.reveal()))
        write_password(self.service, check_key(key), encoded, self.keychain, label=_LABEL)
        if self.get(key) != value:
            raise KeychainError("keychain-write", f"keychain did not store {key}")

    def delete(self, key: str) -> bool:
        result = proc.run(
            [
                SECURITY,
                "delete-generic-password",
                "-s",
                self.service,
                "-a",
                check_key(key),
                *self._target(),
            ]
        )
        if result.returncode == ITEM_NOT_FOUND:
            return False
        if not result.ok:
            raise KeychainError("keychain-delete", f"keychain refused to delete {key}")
        return True

    def keys(self) -> list[str]:
        """Account names of this service's items (attributes only; no secrets read)."""
        result = proc.run([SECURITY, "dump-keychain", *self._target()])
        if not result.ok:
            raise KeychainError("keychain-list", "keychain refused to list items")
        found: list[str] = []
        for block in result.stdout.decode("utf-8", "replace").split("keychain: ")[1:]:
            service = re.search(r'"svce"<blob>="([^"]*)"', block)
            account = re.search(r'"acct"<blob>="([^"]*)"', block)
            if service and account and service.group(1) == self.service:
                found.append(account.group(1))
        return sorted(found)


def read_password(service: str, account: str, keychain: str | None = None) -> Sensitive | None:
    """The raw password bytes of one item, or None if there is no such item."""
    result = proc.run(
        [
            SECURITY,
            "find-generic-password",
            "-s",
            service,
            "-a",
            account,
            "-w",
            *([keychain] if keychain else []),
        ]
    )
    if result.returncode == ITEM_NOT_FOUND:
        return None
    if not result.ok:
        raise KeychainError(
            "keychain-read", "keychain refused a read (is the login keychain unlocked?)"
        )
    data = result.stdout
    return Sensitive(data[:-1] if data.endswith(b"\n") else data)


def _quoted(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9._:/ -]+", value):
        raise ValueError("value cannot be passed to security -i safely")
    return f'"{value}"'


def write_password(
    service: str,
    account: str,
    value: Sensitive,
    keychain: str | None = None,
    label: str | None = None,
) -> None:
    """Create or update one item. The value travels on stdin only, hex-encoded."""
    parts = ["add-generic-password", "-U", "-s", _quoted(service), "-a", _quoted(account)]
    if label:
        parts += ["-l", _quoted(label)]
    parts += ["-X", value.reveal().hex()]
    if keychain:
        parts.append(_quoted(keychain))
    command = (" ".join(parts) + "\n").encode()
    result = proc.run([SECURITY, "-i"], input=command)
    if not result.ok:
        raise KeychainError(
            "keychain-write", "keychain refused a write (is the login keychain unlocked?)"
        )
