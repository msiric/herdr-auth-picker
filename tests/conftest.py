from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


import pytest  # noqa: E402


@pytest.fixture(autouse=True)
def _no_real_herdr(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    """Tests never talk to the herdr running on this machine."""
    if "real_herdr_binary" in request.fixturenames:
        return
    monkeypatch.setattr("auth_picker.herdr.binary", lambda: None)
