"""Opt-in usage: how much of the live account's allowance is used.

The only module that touches the network (design §9, invariant I7):

- One hand-built opener: HTTPS only, no redirect handler (a 30x is an
  error, so a token is never forwarded anywhere), no proxy handler, no
  http/file/ftp/data handlers.
- Two fixed hosts, GET only, an honest User-Agent, 5 s timeout, 64 KiB cap.
- Only the live login's current access token, and only while its clock
  says it is valid. A 401 is not retried. Nothing here renews a token.
- Results are cached without secrets, keyed by account fingerprint, and
  read by the badge and picker without any network.

Both endpoints are undocumented and may change or go away.
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import math
import os
import time
from collections.abc import Callable, Iterator, Mapping
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

if TYPE_CHECKING:  # the network modules load only when a read actually happens
    import ssl
    import urllib.request

from auth_picker import __version__
from auth_picker.backends.base import Snapshot, secret_object
from auth_picker.errors import AuthPickerError
from auth_picker.fsutil import read_private, secure_dir, write_private

CLAUDE_URL = "https://api.anthropic.com/api/oauth/usage"
CODEX_URL = "https://chatgpt.com/backend-api/wham/usage"
ALLOWED_HOSTS = frozenset({"api.anthropic.com", "chatgpt.com"})
USER_AGENT = f"msiric-auth-picker/{__version__}"
TIMEOUT_S = 5.0
MAX_RESPONSE_BYTES = 64 * 1024
DEFAULT_BACKOFF_S = 300.0
MIN_BACKOFF_S, MAX_BACKOFF_S = 60.0, 3600.0
HTTP_OK, HTTP_UNAUTHORIZED, HTTP_TOO_MANY = 200, 401, 429


class UsageError(AuthPickerError):
    """A usage read that did not produce numbers."""


@dataclass(frozen=True)
class Window:
    label: str
    percent: float | None
    resets_at: float | None


@dataclass
class Reading:
    read_at: float | None = None
    windows: list[Window] = field(default_factory=list)
    error: str | None = None
    retry_after: float | None = None
    tried_at: float | None = None


# -- HTTP -----------------------------------------------------------------------


def build_opener(context: ssl.SSLContext | None = None) -> urllib.request.OpenerDirector:
    """An opener that can do HTTPS and nothing else: no redirects, no proxies."""
    import ssl  # noqa: PLC0415 - ~30 ms of imports, needed only when reading usage
    import urllib.request  # noqa: PLC0415

    opener = urllib.request.OpenerDirector()
    opener.add_handler(urllib.request.HTTPSHandler(context=context or ssl.create_default_context()))
    opener.add_handler(urllib.request.HTTPDefaultErrorHandler())
    opener.add_handler(urllib.request.HTTPErrorProcessor())
    return opener


Response = tuple[int, Mapping[str, str], bytes]
Transport = Callable[[str, Mapping[str, str]], Response]


def request(
    opener: urllib.request.OpenerDirector, url: str, headers: Mapping[str, str]
) -> Response:
    """One GET. Returns (status, headers, body) for any HTTP answer."""
    if urlsplit(url).scheme != "https":
        raise UsageError("scheme", "usage is only ever read over https")
    import urllib.error  # noqa: PLC0415
    import urllib.request  # noqa: PLC0415

    # The scheme is checked above, and this opener has no file/ftp/data handlers.
    req = urllib.request.Request(url, headers=dict(headers), method="GET")  # noqa: S310
    try:
        response = opener.open(req, timeout=TIMEOUT_S)
    except urllib.error.HTTPError as exc:
        with exc:
            return exc.code, dict(exc.headers or {}), exc.read(MAX_RESPONSE_BYTES)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise UsageError(
            "unreachable", f"usage endpoint unreachable ({type(exc).__name__})"
        ) from None
    with response:
        body = response.read(MAX_RESPONSE_BYTES + 1)
        if len(body) > MAX_RESPONSE_BYTES:
            raise UsageError("too-large", "usage answer was too large")
        return response.status, dict(response.headers), body


def default_transport() -> Transport:
    opener = build_opener()

    def send(url: str, headers: Mapping[str, str]) -> Response:
        if urlsplit(url).hostname not in ALLOWED_HOSTS:
            raise UsageError("host", "usage is only read from the providers' own hosts")
        return request(opener, url, headers)

    return send


# -- providers ------------------------------------------------------------------


def _number(value: Any) -> float | None:
    return float(value) if isinstance(value, int | float) and not isinstance(value, bool) else None


def _when(value: Any) -> float | None:
    if isinstance(value, int | float) and not isinstance(value, bool):
        return float(value)
    if isinstance(value, str):
        with contextlib.suppress(ValueError):
            return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    return None


def parse_claude(body: Any, now: float) -> list[Window]:
    del now  # same signature as parse_codex
    windows: list[Window] = []
    if not isinstance(body, dict):
        return windows
    for name, label in (("five_hour", "session"), ("seven_day", "weekly")):
        block = body.get(name)
        if isinstance(block, dict):
            windows.append(
                Window(label, _number(block.get("utilization")), _when(block.get("resets_at")))
            )
    return windows


def window_label(seconds: float) -> str | None:
    """Name a window by its length: session, weekly, monthly, or N days."""
    days = seconds / 86400
    if not seconds:
        return None
    if days < 1:
        return "session"
    if 6 <= days <= 8:  # noqa: PLR2004 - "about a week"
        return "weekly"
    if 28 <= days <= 31:  # noqa: PLR2004 - "about a month"
        return "monthly"
    return f"{round(days)}d"


def parse_codex(body: Any, now: float) -> list[Window]:
    rate = body.get("rate_limit") if isinstance(body, dict) else None
    windows: list[Window] = []
    if not isinstance(rate, dict):
        return windows
    for name in ("primary_window", "secondary_window"):
        block = rate.get(name)
        if not isinstance(block, dict):
            continue
        label = window_label(_number(block.get("limit_window_seconds")) or 0) or name.split("_")[0]
        resets = _when(block.get("reset_at"))
        after = _number(block.get("reset_after_seconds"))
        if resets is None and after is not None:
            resets = now + after
        windows.append(Window(label, _number(block.get("used_percent")), resets))
    return windows


def _claude_request(obj: dict[str, Any], now: float) -> tuple[str, dict[str, str]] | None:
    oauth = obj["credentials"].get("claudeAiOauth") or {}
    token, expires = oauth.get("accessToken"), _number(oauth.get("expiresAt"))
    if not isinstance(token, str) or (expires is not None and expires / 1000 <= now):
        return None
    return CLAUDE_URL, {"Authorization": f"Bearer {token}", "anthropic-beta": "oauth-2025-04-20"}


def _codex_request(
    obj: dict[str, Any], snapshot: Snapshot, now: float
) -> tuple[str, dict[str, str]] | None:
    tokens = obj["auth"].get("tokens") or {}
    token = tokens.get("access_token")
    if not isinstance(token, str) or (
        snapshot.access_expires_at is not None and snapshot.access_expires_at <= now
    ):
        return None
    return CODEX_URL, {
        "Authorization": f"Bearer {token}",
        "chatgpt-account-id": snapshot.identity.account_id,
    }


PARSERS = {"claude": parse_claude, "codex": parse_codex}


# -- the cache and the read -----------------------------------------------------


class Usage:
    def __init__(
        self,
        state_dir: str,
        ttl_s: float,
        transport: Transport | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.state_dir = state_dir
        self.ttl_s = ttl_s
        self.transport = transport
        self.clock = clock
        self.cache_path = os.path.join(state_dir, "usage-cache.json")

    def cached(self) -> dict[str, Reading]:
        data = read_private(self.cache_path, 1024 * 1024)
        if not data:
            return {}
        try:
            raw = json.loads(data)
            return {
                key: Reading(**{**entry, "windows": [Window(**w) for w in entry["windows"]]})
                for key, entry in raw.items()
            }
        except (ValueError, TypeError, KeyError):
            return {}

    def _save(self, readings: dict[str, Reading]) -> None:
        secure_dir(self.state_dir)
        write_private(
            self.cache_path, json.dumps({k: asdict(v) for k, v in readings.items()}).encode()
        )

    @contextlib.contextmanager
    def _single_flight(self) -> Iterator[bool]:
        """True if this process may fetch; False if another one already is."""
        secure_dir(self.state_dir)
        fd = os.open(
            os.path.join(self.state_dir, "usage.lock"),
            os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
        )
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                yield False
                return
            yield True
        finally:
            os.close(fd)

    def refresh(self, snapshot: Snapshot) -> Reading:
        """Read the live account's usage if it is due; otherwise return the cache."""
        now = self.clock()
        with self._single_flight() as mine:
            readings = self.cached()
            current = readings.get(snapshot.fingerprint, Reading())
            due = not current.tried_at or now - current.tried_at >= self.ttl_s
            if not mine or not due or (current.retry_after and now < current.retry_after):
                return current
            current = self._fetch(snapshot, current, now)
            readings[snapshot.fingerprint] = current
            self._save(readings)
            return current

    def _fetch(self, snapshot: Snapshot, previous: Reading, now: float) -> Reading:
        obj = secret_object(snapshot.secret, snapshot.kind)
        built = (
            _claude_request(obj, now)
            if snapshot.kind == "claude"
            else _codex_request(obj, snapshot, now)
        )
        keep = Reading(previous.read_at, previous.windows, None, None, now)
        if built is None:
            keep.error = "access token expired; the CLI renews it on next use"
            return keep
        url, headers = built
        headers |= {"User-Agent": USER_AGENT, "Accept": "application/json"}
        transport = self.transport or default_transport()
        try:
            status, response_headers, body = transport(url, headers)
        except UsageError as exc:
            keep.error = exc.message
            return keep
        if status != HTTP_OK:
            keep.error, keep.retry_after = _refusal(status, response_headers, now)
            return keep
        try:
            windows = PARSERS[snapshot.kind](json.loads(body), now)
        except ValueError:
            windows = []
        if not windows:
            keep.error = "unexpected answer (no usage in it)"
            return keep
        return Reading(now, windows, None, None, now)


def _refusal(status: int, headers: Mapping[str, str], now: float) -> tuple[str, float | None]:
    """What a non-200 answer means, and when to ask again."""
    if status == HTTP_TOO_MANY:
        return "rate limited", now + retry_delay(headers.get("Retry-After"), now)
    if status == HTTP_UNAUTHORIZED:
        return "token not accepted (401); the CLI will renew it", None
    return f"unexpected answer ({status})", None


def retry_delay(value: str | None, now: float) -> float:
    """Seconds to wait after a 429, from Retry-After, kept within sane bounds."""
    seconds: float | None = None
    if value:
        try:
            seconds = float(value)
        except ValueError:
            with contextlib.suppress(TypeError, ValueError):
                from email.utils import parsedate_to_datetime  # noqa: PLC0415

                seconds = parsedate_to_datetime(value).timestamp() - now
    if seconds is None or math.isnan(seconds):
        return DEFAULT_BACKOFF_S
    return min(max(seconds, MIN_BACKOFF_S), MAX_BACKOFF_S)


SHORT_LABELS = {"session": "5h", "weekly": "wk", "monthly": "mo"}


def _left(seconds: int) -> str:
    days, hours, minutes = seconds // 86400, (seconds % 86400) // 3600, (seconds % 3600) // 60
    return f"{days}d" if days else f"{hours}h{minutes:02d}"


def compact(reading: Reading | None, now: float, ttl_s: float) -> str:
    """ "42% 5h ↺2h10": fits a sidebar row. "~" marks an old reading."""
    if reading is None or not reading.windows:
        return ""
    window = next((w for w in reading.windows if w.label == "session"), reading.windows[0])
    if window.percent is None:
        return ""
    stale = reading.read_at is None or now - reading.read_at > 2 * ttl_s
    label = SHORT_LABELS.get(window.label, window.label)
    text = f"{'~' if stale else ''}{round(window.percent)}% {label}"
    if window.resets_at and window.resets_at > now:
        text += f" ↺{_left(int(window.resets_at - now))}"
    return text


def summary(reading: Reading | None, now: float, ttl_s: float) -> str:
    """ "42% session, resets 2h10" (or "~42%" when old), for the picker and badge."""
    if reading is None or not reading.windows:
        return ""
    window = next((w for w in reading.windows if w.label == "session"), reading.windows[0])
    if window.percent is None:
        return ""
    stale = reading.read_at is None or now - reading.read_at > 2 * ttl_s
    text = f"{'~' if stale else ''}{round(window.percent)}% {window.label}"
    if window.resets_at and window.resets_at > now:
        left = int(window.resets_at - now)
        days, hours, minutes = left // 86400, (left % 86400) // 3600, (left % 3600) // 60
        text += f", resets {days}d{hours:02d}h" if days else f", resets {hours}h{minutes:02d}"
    return text
