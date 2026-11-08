"""Which account is live, as a short badge for herdr's sidebar and tab bar.

The badge runs every few seconds from a tab bar. It does no network, no
writes, and no Keychain read: Claude's identity comes from its config file.
"""

from __future__ import annotations

import time
from collections.abc import Sequence

from auth_picker import herdr, usage
from auth_picker.app import App

SHORT = {"claude": "Claude", "codex": "Codex"}
UNSAVED = "*"


def label_for(app: App, kind: str) -> str | None:
    """None when there is nothing worth showing for this kind."""
    backend = app.backends[kind]
    saved = app.profiles.of_kind(kind)
    if not saved:
        return None
    identity = backend.live_identity()
    if identity is None:
        return "logged out"
    profile = app.profiles.by_fingerprint(kind, identity.fingerprint(kind))
    label = (
        profile.label
        if profile
        else (identity.email or identity.account_id).split("@")[0] + UNSAVED
    )
    return ("!" if app.journals.rescues(kind) else "") + label


def render(fmt: str, glyph: str, label: str, kind: str, used: str = "") -> str:
    text = fmt.replace("{glyph}", glyph).replace("{label}", label).replace("{kind}", SHORT[kind])
    return text.replace("{usage}", used).strip()


def used_for(app: App, kind: str) -> str:
    """{usage} in the tab bar: the same text as the sidebar's $usage."""
    return usage_token(app, kind)


def line(app: App, kinds: Sequence[str]) -> str:
    shown = [(kind, label) for kind in kinds if (label := label_for(app, kind)) is not None]
    prefix = len(shown) > 1 and "{kind}" not in app.config.badge_format
    return " · ".join(
        (f"{SHORT[kind]} " if prefix else "")
        + render(app.config.badge_format, app.config.glyph, label, kind, used_for(app, kind))
        for kind, label in shown
    )


USAGE_TOKENS = (herdr.USAGE_FIELD, "usage_5h", "usage_wk")


def usage_tokens(app: App, kind: str) -> dict[str, str]:
    """$usage (per usage.style), $usage_5h and $usage_wk for the live account.

    From the cache only: no network, no secrets. Empty values mean "clear it".
    """
    empty = dict.fromkeys(USAGE_TOKENS, "")
    if app.usage is None:
        return empty
    identity = app.backends[kind].live_identity()
    if identity is None:
        return empty
    reading = app.usage.cached().get(identity.fingerprint(kind))
    now, ttl = time.time(), app.config.usage.ttl_s
    return {
        herdr.USAGE_FIELD: usage.compact(reading, now, ttl, app.config.usage.style),
        "usage_5h": usage.window_token(reading, now, ttl, "session"),
        "usage_wk": usage.window_token(reading, now, ttl, "weekly"),
    }


def usage_token(app: App, kind: str) -> str:
    return usage_tokens(app, kind)[herdr.USAGE_FIELD]


def stamp(app: App, panes: set[str] | None = None) -> None:
    """Put $acct (and $usage, if usage is on) on Claude/Codex panes herdr knows.

    ``panes`` limits it to those pane ids. Reads no secrets and no network.
    """
    if not app.config.badge:
        return
    labels = {kind: label_for(app, kind) for kind in app.backends}
    used = {kind: usage_tokens(app, kind) for kind in app.backends}
    for agent in herdr.agents():
        kind = herdr.kind_of_agent(agent)
        pane = agent["pane_id"]
        if kind is None or (panes is not None and pane not in panes):
            continue
        mine = used[kind]
        tokens = {name: value for name, value in mine.items() if value}
        label = labels.get(kind)
        if label:
            tokens[herdr.BADGE_FIELD] = render(
                app.config.badge_format, app.config.glyph, label, kind, mine[herdr.USAGE_FIELD]
            )
        herdr.report(pane, tokens, tuple(name for name, value in mine.items() if not value))
