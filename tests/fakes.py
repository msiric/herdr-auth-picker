"""Fake logins for backend tests. Every token here is made up."""

from __future__ import annotations

import base64
import json
import time
from pathlib import Path
from typing import Any


def jwt(claims: dict[str, Any]) -> str:
    def part(obj: dict[str, Any]) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()

    return f"{part({'alg': 'none'})}.{part(claims)}.c2ln"


def claude_blob(who: str, generation: int = 1, **machine: Any) -> dict[str, Any]:
    now_ms = int(time.time() * 1000)
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
            "access_token": jwt({"exp": int(time.time()) + 3600, "g": generation}),
            "refresh_token": f"rt_{who}_{generation}",
            "account_id": account,
        },
        "last_refresh": "2026-10-28T18:36:53.123456Z",
    }
