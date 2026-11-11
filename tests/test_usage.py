from __future__ import annotations

import fcntl
import http.server
import json
import shutil
import ssl
import subprocess
import threading
from collections.abc import Iterator, Mapping
from pathlib import Path

import pytest

from auth_picker.backends.base import Snapshot
from auth_picker.redact import Sensitive
from auth_picker.usage import (
    MAX_BACKOFF_S,
    MIN_BACKOFF_S,
    Reading,
    Usage,
    UsageError,
    Window,
    build_opener,
    default_transport,
    request,
    retry_delay,
    summary,
)
from tests.fakes import NOW, claude_secret, codex_secret, make_backends

# -- the opener, against a real local HTTPS server --------------------------------


class Server:
    def __init__(self, port: int, context: ssl.SSLContext, hits: list[str]) -> None:
        self.base = f"https://localhost:{port}"
        self.client_context = context
        self.hits = hits


@pytest.fixture(scope="module")
def server(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Server]:
    openssl = shutil.which("openssl")
    if openssl is None:
        pytest.skip("openssl is needed to make a test certificate")
    tmp = tmp_path_factory.mktemp("tls")
    cert, key = tmp / "cert.pem", tmp / "key.pem"
    subprocess.run(
        [
            openssl,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost",
        ],
        check=True,
        capture_output=True,
    )
    hits: list[str] = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            hits.append(self.path)
            if self.path == "/redirect":
                self.send_response(302)
                self.send_header("Location", "/leak")
                self.end_headers()
                return
            body = b"x" * 70_000 if self.path == "/big" else b'{"ok": true}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args: object) -> None:
            pass

    httpd = http.server.HTTPServer(("localhost", 0), Handler)
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(cert, key)
    httpd.socket = server_context.wrap_socket(httpd.socket, server_side=True)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    client = ssl.create_default_context(cafile=str(cert))
    try:
        yield Server(httpd.server_address[1], client, hits)
    finally:
        httpd.shutdown()


def test_a_redirect_is_never_followed(server: Server) -> None:
    opener = build_opener(server.client_context)
    status, _headers, _body = request(
        opener, server.base + "/redirect", {"Authorization": "Bearer secret"}
    )
    assert status == 302
    assert "/leak" not in server.hits


def test_oversized_answers_are_refused(server: Server) -> None:
    with pytest.raises(UsageError, match="too large"):
        request(build_opener(server.client_context), server.base + "/big", {})


def test_proxy_settings_are_ignored(server: Server, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("https_proxy", "http://127.0.0.1:9")
    status, _headers, body = request(build_opener(server.client_context), server.base + "/ok", {})
    assert (status, json.loads(body)) == (200, {"ok": True})


def test_only_https_and_only_the_providers(server: Server) -> None:
    with pytest.raises(UsageError, match="https"):
        request(build_opener(), "http://localhost/", {})
    with pytest.raises(UsageError, match="providers' own hosts"):
        default_transport()(server.base + "/ok", {})


# -- the read, with a fake transport ---------------------------------------------


class Provider:
    def __init__(self, answers: list[tuple[int, dict[str, str], object]]) -> None:
        self.answers = answers
        self.calls: list[tuple[str, Mapping[str, str]]] = []

    def __call__(
        self, url: str, headers: Mapping[str, str]
    ) -> tuple[int, Mapping[str, str], bytes]:
        self.calls.append((url, headers))
        status, response_headers, body = self.answers.pop(0)
        return status, response_headers, json.dumps(body).encode()


CLAUDE_OK = {
    "five_hour": {"utilization": 42.0, "resets_at": NOW + 3600},
    "seven_day": {"utilization": 9.0, "resets_at": "2099-01-01T00:00:00Z"},
}


@pytest.fixture
def snapshot(tmp_path: Path) -> Snapshot:
    backend = make_backends(tmp_path)["claude"]
    parsed: Snapshot = backend.parse_secret(Sensitive(claude_secret("alice")))
    return parsed


def _usage(tmp_path: Path, provider: Provider, clock: list[float]) -> Usage:
    return Usage(str(tmp_path / "state"), 300, transport=provider, clock=lambda: clock[0])


def test_reads_are_cached_and_hold_no_token(tmp_path: Path, snapshot: Snapshot) -> None:
    provider = Provider([(200, {}, CLAUDE_OK)])
    clock = [float(NOW)]
    usage = _usage(tmp_path, provider, clock)
    reading = usage.refresh(snapshot)
    assert [w.label for w in reading.windows] == ["session", "weekly"]
    assert provider.calls[0][1]["User-Agent"].startswith("msiric-auth-picker/")
    assert "sk-ant" not in (tmp_path / "state" / "usage-cache.json").read_text()

    clock[0] += 100
    assert usage.refresh(snapshot).windows == reading.windows
    assert len(provider.calls) == 1  # within the TTL: no request


def test_rate_limits_are_respected(tmp_path: Path, snapshot: Snapshot) -> None:
    provider = Provider([(200, {}, CLAUDE_OK), (429, {"Retry-After": "900"}, {})])
    clock = [float(NOW)]
    usage = _usage(tmp_path, provider, clock)
    usage.refresh(snapshot)
    clock[0] += 400
    limited = usage.refresh(snapshot)
    assert limited.error == "rate limited"
    assert limited.windows  # the last reading is kept
    clock[0] += 400  # past the TTL, but not past Retry-After
    usage.refresh(snapshot)
    assert len(provider.calls) == 2


def test_an_expired_token_is_never_sent(tmp_path: Path) -> None:
    backend = make_backends(tmp_path)["claude"]
    obj = json.loads(claude_secret("alice"))
    obj["credentials"]["claudeAiOauth"]["expiresAt"] = 1000
    snapshot = backend.parse_secret(Sensitive(json.dumps(obj).encode()))
    provider = Provider([])
    reading = _usage(tmp_path, provider, [float(NOW)]).refresh(snapshot)
    assert provider.calls == []
    assert "expired" in (reading.error or "")


def test_codex_windows(tmp_path: Path) -> None:
    snapshot = make_backends(tmp_path)["codex"].parse_secret(Sensitive(codex_secret("bob")))
    body = {
        "rate_limit": {
            "primary_window": {
                "used_percent": 30,
                "limit_window_seconds": 18000,
                "reset_after_seconds": 600,
            }
        }
    }
    provider = Provider([(200, {}, body)])
    reading = _usage(tmp_path, provider, [float(NOW)]).refresh(snapshot)
    assert reading.windows == [Window("session", 30.0, NOW + 600)]
    assert provider.calls[0][1]["chatgpt-account-id"] == "ws-bob"


def test_only_one_process_fetches_at_a_time(tmp_path: Path, snapshot: Snapshot) -> None:
    provider = Provider([])
    usage = _usage(tmp_path, provider, [float(NOW)])
    (tmp_path / "state").mkdir(mode=0o700)
    with open(tmp_path / "state" / "usage.lock", "w") as held:
        fcntl.flock(held, fcntl.LOCK_EX)
        assert usage.refresh(snapshot) == Reading()
    assert provider.calls == []


@pytest.mark.parametrize(
    ("value", "seconds"),
    [
        ("120", 120.0),
        ("5", MIN_BACKOFF_S),
        ("999999", MAX_BACKOFF_S),
        ("nan", 300.0),
        ("soon", 300.0),
        (None, 300.0),
    ],
)
def test_retry_delay_is_bounded(value: str | None, seconds: float) -> None:
    assert retry_delay(value, float(NOW)) == seconds


def test_summary_marks_old_readings() -> None:
    fresh = Reading(read_at=NOW, windows=[Window("session", 41.6, NOW + 7800)])
    assert summary(fresh, NOW, 300) == "42% session, resets 2h10"
    assert summary(fresh, NOW + 3600, 300).startswith("~42%")
    assert summary(None, NOW, 300) == ""


@pytest.mark.parametrize(
    ("seconds", "label"),
    [(18000, "session"), (604800, "weekly"), (2592000, "monthly"), (1209600, "14d"), (0, None)],
)
def test_windows_are_named_by_length(seconds: int, label: str | None) -> None:
    from auth_picker.usage import window_label  # noqa: PLC0415

    assert window_label(seconds) == label


def test_long_resets_read_in_days() -> None:
    reading = Reading(read_at=NOW, windows=[Window("monthly", 3.0, NOW + 30 * 86400)])
    assert summary(reading, NOW, 300) == "3% monthly, resets 30d00h"


def test_compact_fits_a_sidebar_row() -> None:
    from auth_picker.usage import compact  # noqa: PLC0415

    reading = Reading(read_at=NOW, windows=[Window("session", 41.6, NOW + 7800)])
    assert compact(reading, NOW, 300) == "42% 5h ↺2h10"
    assert compact(reading, NOW + 3600, 300).startswith("~42%")
    monthly = Reading(read_at=NOW, windows=[Window("monthly", 3.0, NOW + 29 * 86400 + 60)])
    assert compact(monthly, NOW, 300) == "3% mo ↺29d"
    assert compact(None, NOW, 300) == ""


CLAUDE_LIMITS = {
    "five_hour": {"utilization": 12.0, "resets_at": "2099-01-01T00:00:00Z"},
    "limits": [
        {
            "kind": "session",
            "group": "session",
            "percent": 12,
            "resets_at": NOW + 3600,
            "scope": None,
            "is_active": False,
        },
        {
            "kind": "weekly_all",
            "group": "weekly",
            "percent": 37,
            "resets_at": NOW + 3 * 86400,
            "scope": None,
            "is_active": True,
        },
        {
            "kind": "weekly_scoped",
            "group": "weekly",
            "percent": 7,
            "resets_at": NOW + 3 * 86400,
            "scope": {"model": {"id": None, "display_name": "Fable"}},
            "is_active": False,
        },
    ],
}


def test_claude_limits_list_is_read_whole() -> None:
    from auth_picker.usage import parse_claude  # noqa: PLC0415

    windows = parse_claude(CLAUDE_LIMITS, NOW)
    assert [(w.label, w.percent, w.scope, w.active) for w in windows] == [
        ("session", 12.0, None, False),
        ("weekly", 37.0, None, True),
        ("weekly", 7.0, "Fable", False),
    ]


def test_a_per_model_window_without_a_name_is_still_per_model() -> None:
    from auth_picker.usage import binding, parse_claude  # noqa: PLC0415

    body = {
        "limits": [
            {"kind": "weekly_all", "percent": 20, "resets_at": NOW + 86400, "scope": None},
            {
                "kind": "weekly_scoped",
                "percent": 90,
                "resets_at": NOW + 86400,
                "scope": {"model": {"id": None, "display_name": None}},
            },
        ]
    }
    windows = parse_claude(body, NOW)
    assert [w.scope for w in windows] == [None, "model"]
    chosen = binding(windows)
    assert chosen is not None
    assert chosen.percent == 20.0


def _w(label: str, percent: float, resets: float = NOW + 3600, **kw: object) -> Window:
    return Window(label, percent, resets, **kw)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("windows", "expected"),
    [
        # the most used account-wide window
        ([_w("session", 12), _w("weekly", 37)], ("weekly", 37.0)),
        ([_w("session", 85), _w("weekly", 37)], ("session", 85.0)),
        # a tie goes to the provider's flag, then the shorter window
        ([_w("session", 40), _w("weekly", 40, active=True)], ("weekly", 40.0)),
        ([_w("session", 40), _w("weekly", 40)], ("session", 40.0)),
        # a per-model window counts only once it is full
        ([_w("session", 10), _w("weekly", 20), _w("weekly", 90, scope="Fable")], ("weekly", 20.0)),
        ([_w("session", 10), _w("weekly", 100, scope="Fable")], ("weekly", 100.0)),
        # several full: the one that frees up last
        ([_w("session", 100, NOW + 60), _w("weekly", 100, NOW + 86400)], ("weekly", 100.0)),
    ],
)
def test_the_binding_window(windows: list[Window], expected: tuple[str, float]) -> None:
    from auth_picker.usage import binding  # noqa: PLC0415

    chosen = binding(windows)
    assert chosen is not None
    assert (chosen.label, chosen.percent) == expected


def test_usage_styles_and_window_tokens() -> None:
    from auth_picker.usage import (  # noqa: PLC0415
        compact,
        details,
        parse_claude,
        window_token,
    )

    reading = Reading(read_at=NOW, windows=parse_claude(CLAUDE_LIMITS, NOW))
    assert compact(reading, NOW, 300) == "37% wk ↺3d00h"
    assert compact(reading, NOW, 300, "both") == "12%·5h 37%·wk"
    assert window_token(reading, NOW, 300, "session") == "12% 5h ↺1h00"
    assert window_token(reading, NOW, 300, "monthly") == ""
    assert details(reading, NOW)[0].startswith("37% weekly")
    assert any("Fable" in line for line in details(reading, NOW))
    full = Reading(read_at=NOW, windows=[_w("session", 100, NOW + 600), _w("weekly", 50)])
    assert compact(full, NOW, 300, "both") == "100% 5h ↺0h10"  # blocked wins over "both"
