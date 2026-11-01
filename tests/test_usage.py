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
