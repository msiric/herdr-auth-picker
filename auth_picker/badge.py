"""Which account is live, as a short badge for herdr's sidebar and tab bar.

The badge runs every few seconds from a tab bar. It does no network, no
writes, and no Keychain read: Claude's identity comes from its config file.
"""

from __future__ import annotations

from collections.abc import Sequence

from auth_picker import herdr
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


def render(fmt: str, glyph: str, label: str, kind: str) -> str:
    return fmt.replace("{glyph}", glyph).replace("{label}", label).replace("{kind}", SHORT[kind])


def line(app: App, kinds: Sequence[str]) -> str:
    shown = [(kind, label) for kind in kinds if (label := label_for(app, kind)) is not None]
    prefix = len(shown) > 1 and "{kind}" not in app.config.badge_format
    return " · ".join(
        (f"{SHORT[kind]} " if prefix else "")
        + render(app.config.badge_format, app.config.glyph, label, kind)
        for kind, label in shown
    )


def stamp(app: App) -> None:
    """Put the badge on every Claude/Codex pane herdr knows about."""
    if not app.config.badge:
        return
    labels = {kind: label_for(app, kind) for kind in app.backends}
    for agent in herdr.agents():
        kind = herdr.kind_of_agent(agent)
        label = labels.get(kind) if kind else None
        if kind and label:
            herdr.set_badge(
                agent["pane_id"], render(app.config.badge_format, app.config.glyph, label, kind)
            )
