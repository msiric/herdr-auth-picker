"""Secrets as generic-password items in a macOS keychain, via /usr/bin/security.

Writes go through ``security -i`` with the command on stdin and the value as
``-X <hex>``. The value never appears in any process's argv, and no quoting
can go wrong. Do not use ``add-generic-password -w`` with a piped stdin: it
fails its retype prompt, exits 0, and stores an EMPTY password (verified on
macOS 26.7.1; this is how the original plugin blanked logins).

``security -i`` reads at most about 4,090 characters per command and runs a
longer one in pieces, storing a truncated value (verified on macOS 26.7.1).
Every write is therefore checked against ``MAX_COMMAND_BYTES`` before anything
runs, and our own secrets are split into parts that fit:

- the item named by the key holds a small manifest: part count, generation
  and SHA-256 of the whole value;
- the parts are ``<key>.<generation>.<n>``. New parts are written first, then
  the manifest, then the previous generation's parts are deleted. A crash at
  any point leaves the old value or the new one readable, never a mix.

Our items hold base64 text, so ``find-generic-password -w`` always prints them
verbatim (``security`` switches to hex for non-printable data).

Every item is in the login keychain unless ``keychain`` names another file;
tests use a throwaway keychain file and never touch the login keychain.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import hashlib
import json
import re

from auth_picker import proc
from auth_picker.errors import AuthPickerError
from auth_picker.redact import Sensitive
from auth_picker.secretstore.base import check_key

SECURITY = "/usr/bin/security"
ITEM_NOT_FOUND = 44  # errSecItemNotFound, as security(1) reports it
_LABEL = "auth-picker saved login"
# security -i handles commands up to about 4,090 characters; stay well clear.
MAX_COMMAND_BYTES = 4000
# Raw bytes per part: base64 (x4/3), then hex (x2), plus the command around it.
PART_BYTES = 1200
_MANIFEST = "auth-picker-parts"
_PART = re.compile(r"\.[0-9a-f]{12}\.\d+$")
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

    def _get_raw(self, account: str) -> bytes | None:
        raw = read_password(self.service, account, self.keychain)
        if raw is None:
            return None
        try:
            return base64.b64decode(raw.reveal().strip(), validate=True)
        except binascii.Error:
            raise KeychainError(
                "keychain-format", f"keychain item {account} is not in the expected format"
            ) from None

    def _put_raw(self, account: str, data: bytes) -> None:
        write_password(
            self.service, account, Sensitive(base64.b64encode(data)), self.keychain, label=_LABEL
        )

    def _manifest(self, key: str) -> tuple[bytes | None, dict[str, object] | None]:
        data = self._get_raw(key)
        if data is None:
            return None, None
        try:
            manifest = json.loads(data)
        except ValueError:
            return data, None
        if isinstance(manifest, dict) and manifest.get(_MANIFEST) == 1:
            return data, manifest
        return data, None

    def get(self, key: str) -> Sensitive | None:
        data, manifest = self._manifest(check_key(key))
        if data is None:
            return None
        if manifest is None:
            return Sensitive(data)  # a value small enough to have been stored whole
        generation, count = str(manifest["g"]), int(str(manifest["n"]))
        parts = [self._get_raw(f"{key}.{generation}.{n}") for n in range(count)]
        if any(part is None for part in parts):
            raise KeychainError("keychain-parts", f"keychain item {key} is missing parts")
        value = b"".join(p for p in parts if p is not None)
        if hashlib.sha256(value).hexdigest() != manifest["sha256"]:
            raise KeychainError("keychain-parts", f"keychain item {key} does not add up")
        return Sensitive(value)

    def put(self, key: str, value: Sensitive) -> None:
        check_key(key)
        data = value.reveal()
        _, old = self._manifest(key)
        digest = hashlib.sha256(data).hexdigest()
        generation = digest[:12]
        chunks = [data[i : i + PART_BYTES] for i in range(0, len(data), PART_BYTES)] or [b""]
        for n, chunk in enumerate(chunks):
            self._put_raw(f"{key}.{generation}.{n}", chunk)
        manifest = {_MANIFEST: 1, "g": generation, "n": len(chunks), "sha256": digest}
        self._put_raw(key, json.dumps(manifest).encode())
        if self.get(key) != value:
            raise KeychainError("keychain-write", f"keychain did not store {key}")
        if old is not None and old.get("g") != generation:
            self._delete_parts(key, old)

    def _delete_parts(self, key: str, manifest: dict[str, object]) -> None:
        for n in range(int(str(manifest.get("n", 0)))):
            self._delete_account(f"{key}.{manifest.get('g')}.{n}")

    def _delete_account(self, account: str) -> bool:
        result = proc.run(
            [
                SECURITY,
                "delete-generic-password",
                "-s",
                self.service,
                "-a",
                account,
                *self._target(),
            ]
        )
        if result.returncode == ITEM_NOT_FOUND:
            return False
        if not result.ok:
            raise KeychainError("keychain-delete", f"keychain refused to delete {account}")
        return True

    def delete(self, key: str) -> bool:
        manifest = None
        # A damaged item (for one, a truncated write) must still be deletable.
        with contextlib.suppress(KeychainError):
            _, manifest = self._manifest(check_key(key))
        existed = self._delete_account(key)
        if manifest is not None:
            self._delete_parts(key, manifest)
        return existed

    def keys(self) -> list[str]:
        """Account names of this service's items (attributes only; no secrets read)."""
        result = proc.run([SECURITY, "dump-keychain", *self._target()])
        if not result.ok:
            raise KeychainError("keychain-list", "keychain refused to list items")
        found: list[str] = []
        for block in result.stdout.decode("utf-8", "replace").split("keychain: ")[1:]:
            service = re.search(r'"svce"<blob>="([^"]*)"', block)
            account = re.search(r'"acct"<blob>="([^"]*)"', block)
            if (
                service
                and account
                and service.group(1) == self.service
                and not _PART.search(account.group(1))
            ):
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
    if len(command) > MAX_COMMAND_BYTES:
        # security -i would run this in pieces and store a truncated value.
        raise KeychainError(
            "keychain-too-large",
            f"{len(value.reveal())} bytes is too large to write to the keychain safely",
        )
    result = proc.run([SECURITY, "-i"], input=command)
    if not result.ok:
        raise KeychainError(
            "keychain-write", "keychain refused a write (is the login keychain unlocked?)"
        )
