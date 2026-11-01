"""Keep secrets out of output.

``Sensitive`` wraps a secret so that formatting it by accident prints a
placeholder. ``redact`` is the last line of defence on every output path: it
masks anything shaped like a token before text leaves the process.
"""

from __future__ import annotations

import hmac
import re
from typing import NoReturn

_PATTERNS = (
    # Anthropic OAuth and API tokens.
    (re.compile(r"sk-ant-[A-Za-z0-9_\-]{8,}"), "sk-ant-[REDACTED]"),
    # JWTs (OpenAI id/access tokens).
    (
        re.compile(r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]*"),
        "[REDACTED-JWT]",
    ),
    # Bearer headers, whatever follows.
    (re.compile(r"(?i)(bearer\s+)\S+"), r"\1[REDACTED]"),
)

# Long runs of token alphabet that mix letters and digits: opaque refresh
# tokens, keys, hex digests. Paths and prose rarely have 32 such characters in
# a row without a "/" or a space.
_OPAQUE = re.compile(r"[A-Za-z0-9_\-+=]{32,}")


def _mask_opaque(match: re.Match[str]) -> str:
    run = match.group(0)
    has_digit = any(c.isdigit() for c in run)
    has_alpha = any(c.isalpha() for c in run)
    return "[REDACTED]" if has_digit and has_alpha else run


def redact(text: str) -> str:
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return _OPAQUE.sub(_mask_opaque, text)


class Sensitive:
    """A secret value that will not print itself.

    ``reveal()`` is the only way to the bytes, which makes every use visible
    in review. Not picklable, and not comparable to anything but another
    Sensitive (constant-time).
    """

    __slots__ = ("_value",)

    def __init__(self, value: bytes) -> None:
        self._value = value

    def reveal(self) -> bytes:
        return self._value

    def __repr__(self) -> str:
        return "Sensitive(<redacted>)"

    __str__ = __repr__

    def __format__(self, _spec: str) -> str:
        return repr(self)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Sensitive):
            return NotImplemented
        return hmac.compare_digest(self._value, other._value)

    def __hash__(self) -> int:
        raise TypeError("Sensitive values are not hashable")

    def __reduce__(self) -> NoReturn:
        raise TypeError("Sensitive values cannot be pickled")
