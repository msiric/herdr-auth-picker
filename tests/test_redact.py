from __future__ import annotations

import pickle

import pytest

from auth_picker.redact import Sensitive, redact

ANTHROPIC = "sk-ant-oat01-AbCdEf0123456789_xyz-QRSTUV"
JWT = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEyMyJ9.c2lnbmF0dXJlLWJ5dGVz"
OPAQUE = "rt_9fK2mQ7xL4pZ8wB1nV6cT3yH5jD0sA2e"


@pytest.mark.parametrize("secret", [ANTHROPIC, JWT, OPAQUE])
def test_token_shapes_are_masked(secret: str) -> None:
    assert secret not in redact(f"failed with {secret} in it")


def test_bearer_header_is_masked() -> None:
    assert "abc.def" not in redact("Authorization: Bearer abc.def")


@pytest.mark.parametrize(
    "text",
    [
        "/Users/someone/.local/state/herdr/plugins/msiric.auth-picker/index.json",
        "switched claude to work (you@example.com · max)",
        "a-very-long-label-made-only-of-words-and-dashes",
    ],
)
def test_ordinary_text_is_left_alone(text: str) -> None:
    assert redact(text) == text


def test_sensitive_never_formats_its_value() -> None:
    value = Sensitive(b"hunter2-token")
    rendered = [repr(value), str(value), f"{value}", "%s" % (value,)]  # noqa: UP031 - %-format is a case under test
    assert not any("hunter2" in r for r in rendered)


def test_sensitive_refuses_pickling_and_hashing() -> None:
    value = Sensitive(b"x")
    with pytest.raises(TypeError):
        pickle.dumps(value)
    with pytest.raises(TypeError):
        hash(value)


def test_sensitive_equality() -> None:
    assert Sensitive(b"a") == Sensitive(b"a")
    assert Sensitive(b"a") != Sensitive(b"b")


def test_uuids_are_ids_not_secrets() -> None:
    text = "unreferenced saved secret profile:2f1c9a7e-5b3d-4c8e-9f10-112233445566"
    assert redact(text) == text
