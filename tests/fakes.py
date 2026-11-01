"""Fake logins for backend tests. Every token here is made up."""

from __future__ import annotations

import base64
import json
import time
from pathlib import Path
from typing import Any

from auth_picker.backends.base import canonical
from auth_picker.backends.claude import ClaudeBackend, FileCredential, resolve_paths
from auth_picker.backends.codex import CodexBackend

# Fixed per test run, so the same fake login is byte-identical every time.
NOW = int(time.time())


def jwt(claims: dict[str, Any]) -> str:
    def part(obj: dict[str, Any]) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()

    return f"{part({'alg': 'none'})}.{part(claims)}.c2ln"


def claude_blob(who: str, generation: int = 1, **machine: Any) -> dict[str, Any]:
    now_ms = NOW * 1000
    return {
        "claudeAiOauth": {
            "accessToken": f"sk-ant-oat01-{who}-access-{generation}",
            "refreshToken": f"sk-ant-ort01-{who}-refresh-{generation}",
            "expiresAt": now_ms + 8 * 3600 * 1000,
            "refreshTokenExpiresAt": now_ms + 30 * 86400 * 1000,
            "scopes": ["user:inference", "user:profile"],
            "subscriptionType": "max",
        },
        "trustedDeviceToken": f"device-{who}",
        **machine,
    }


def claude_account(who: str, org: str = "org-1") -> dict[str, Any]:
    return {
        "accountUuid": f"uuid-{who}",
        "organizationUuid": f"{org}-{who}",
        "emailAddress": f"{who}@example.com",
        "organizationName": f"{who}'s org",
    }


def write_claude_config(path: Path, who: str | None, **extra: Any) -> None:
    config: dict[str, Any] = {"projects": {"/work": {"history": [1, 2, 3]}}, **extra}
    if who is not None:
        config["oauthAccount"] = claude_account(who)
    path.write_text(json.dumps(config, indent=2))


def codex_auth(who: str, generation: int = 1, workspace: str | None = None) -> dict[str, Any]:
    account = workspace or f"ws-{who}"
    id_claims = {
        "email": f"{who}@example.com",
        "https://api.openai.com/auth": {
            "chatgpt_account_id": account,
            "chatgpt_user_id": f"user-{who}",
            "chatgpt_plan_type": "plus",
        },
    }
    return {
        "auth_mode": "chatgpt",
        "OPENAI_API_KEY": None,
        "tokens": {
            "id_token": jwt(id_claims),
            "access_token": jwt({"exp": NOW + 3600, "g": generation}),
            "refresh_token": f"rt_{who}_{generation}",
            "account_id": account,
        },
        "last_refresh": "2026-10-28T18:36:53.123456Z",
    }


def claude_secret(who: str, generation: int = 1) -> bytes:
    blob = claude_blob(who, generation)
    return canonical(
        {"schema": 1, "kind": "claude", "credentials": blob, "oauth_account": claude_account(who)}
    )


def codex_secret(who: str, generation: int = 1) -> bytes:
    return canonical({"schema": 1, "kind": "codex", "auth": codex_auth(who, generation)})


def make_backends(root: Path) -> dict[str, Any]:
    (root / "home" / ".claude").mkdir(parents=True, exist_ok=True)
    (root / "home" / ".codex").mkdir(parents=True, exist_ok=True)
    write_claude_config(root / "home" / ".claude.json", None)
    paths = resolve_paths({"HOME": str(root / "home"), "USER": "alice"})
    return {
        "claude": ClaudeBackend(paths, store=FileCredential(paths.credentials_file)),
        "codex": CodexBackend(str(root / "home" / ".codex")),
    }
