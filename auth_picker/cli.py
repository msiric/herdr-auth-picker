"""Command-line interface: argv in, exit code out.

This is the only place that writes to stdout/stderr, and all of it passes
through ``redact``: herdr keeps both streams in its plugin logs. Commands
herdr runs as actions also report through a herdr notification, because
nobody reads those logs as it happens.
"""

from __future__ import annotations

import argparse
import sys
import time
import traceback
from collections.abc import Callable, Sequence

from auth_picker import __version__, badge, herdr, migrate
from auth_picker.app import App
from auth_picker.backends import KINDS
from auth_picker.backends.base import Unsupported
from auth_picker.errors import AuthPickerError
from auth_picker.redact import redact
from auth_picker.switch import Outcome

Handler = Callable[[argparse.Namespace], int]

EXIT_INTERNAL = 70
EXIT_INTERRUPTED = 130
TITLES = {"claude": "Claude Code", "codex": "Codex"}


def out(text: str) -> None:
    sys.stdout.write(redact(text) + "\n")


def err(text: str) -> None:
    sys.stderr.write(redact(text.rstrip("\n")) + "\n")


def _app(args: argparse.Namespace) -> App:
    return App.load(args.config)


def _kind(app: App, given: str | None) -> str:
    """The kind a command is about: given, else the focused pane's, else the only one."""
    if given:
        return given
    focused = herdr.focused_kind()
    if focused:
        return focused
    with_profiles = [k for k in KINDS if app.profiles.of_kind(k)]
    if len(with_profiles) == 1:
        return with_profiles[0]
    raise AuthPickerError("which-kind", "say which: claude or codex")


def _ago(then: float | None) -> str:
    if not then:
        return "never"
    seconds = int(time.time() - then)
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if seconds >= size:
            return f"{seconds // size}{unit} ago"
    return "just now"


def _after_change(app: App, title: str, body: str) -> None:
    badge.stamp(app)
    if app.config.notify and herdr.invoked_by_herdr():
        herdr.notify(title, body)


def _report(app: App, outcome: Outcome) -> int:
    title = f"{TITLES[outcome.kind]}: {outcome.label}"
    if outcome.status == "already":
        out(f"{outcome.kind}: already on {outcome.label}")
        return 0
    body = outcome.describe if app.config.notify_identity else ""
    out(f"{outcome.kind}: switched to {outcome.label}")
    for note in outcome.notes:
        out(f"  note: {note}")
    _after_change(app, title, "; ".join([b for b in [body, *outcome.notes] if b]))
    return 0


# -- commands -----------------------------------------------------------------


def _cmd_switch(args: argparse.Namespace) -> int:
    app = _app(args)
    return _report(app, app.switcher.switch(args.kind, args.name, force=args.force))


def _cmd_next(args: argparse.Namespace) -> int:
    app = _app(args)
    return _report(app, app.switcher.next(_kind(app, args.kind), force=args.force))


def _cmd_undo(args: argparse.Namespace) -> int:
    app = _app(args)
    return _report(app, app.switcher.undo(_kind(app, args.kind), force=args.force))


def _cmd_save(args: argparse.Namespace) -> int:
    app = _app(args)
    kinds = [args.kind] if args.kind else list(KINDS)
    saved = 0
    for kind in kinds:
        try:
            profile = app.switcher.save(kind, args.name)
        except AuthPickerError as exc:
            if args.kind:
                raise
            out(f"{kind}: {exc.message}")
            continue
        saved += 1
        out(f"{kind}: saved as {profile.label} ({profile.identity.describe()})")
        _after_change(app, f"{TITLES[kind]}: saved", profile.label)
    return 0 if saved else 1


def _cmd_sync(args: argparse.Namespace) -> int:
    app = _app(args)
    kind = _kind(app, args.kind)
    profile = app.switcher.sync(kind)
    out(f"{kind}: {profile.label} now holds the live login")
    return 0


def _cmd_rename(args: argparse.Namespace) -> int:
    app = _app(args)
    profile = app.profiles.rename(app.profiles.find(args.kind, args.name), args.new_name)
    out(f"{args.kind}: renamed to {profile.label}")
    badge.stamp(app)
    return 0


def _cmd_delete(args: argparse.Namespace) -> int:
    app = _app(args)
    profile = app.profiles.find(args.kind, args.name)
    identity = app.backends[args.kind].live_identity()
    live = identity is not None and identity.fingerprint(args.kind) == profile.fingerprint
    if not args.yes:
        where = (
            "it is logged in now, so the login itself stays"
            if live
            else "it is not logged in, so this is the only copy of that login"
        )
        out(f"would delete {profile.label} ({profile.identity.describe()}); {where}")
        out("run again with --yes to delete it")
        return 1
    app.profiles.delete(profile)
    out(f"{args.kind}: deleted {profile.label}")
    badge.stamp(app)
    return 0


def _cmd_rescue(args: argparse.Namespace) -> int:
    app = _app(args)
    rescues = app.journals.rescues()
    if args.clear is None:
        if not rescues:
            out("nothing to resolve")
        for rescue in rescues:
            out(f"{rescue.rid}  {rescue.kind}: {rescue.reason} ({_ago(rescue.created_at)})")
            for entry in rescue.kept:
                out(f"    kept: {entry['what']} {entry['describe']}".rstrip())
        return 0
    match = [r for r in rescues if r.rid == args.clear]
    if not match:
        raise AuthPickerError("missing", f"no rescue {args.clear}")
    if not args.yes:
        out(
            "clearing deletes the logins kept with it; make sure the one you need is live "
            "or saved first, then run again with --yes"
        )
        return 1
    app.journals.clear_rescue(match[0])
    out(f"cleared {args.clear}")
    badge.stamp(app)
    return 0


def _cmd_recover(args: argparse.Namespace) -> int:
    app = _app(args)
    for kind in KINDS:
        try:
            result = app.switcher.recover(kind)
        except AuthPickerError as exc:
            out(f"{kind}: {exc.message}")
            continue
        if result:
            out(f"{kind}: an interrupted switch was {result}")
            if result == "rescued":
                herdr.notify(f"{TITLES[kind]}: needs attention", "run the status action")
    badge.stamp(app)
    return 0


def _cmd_badge(args: argparse.Namespace) -> int:
    unknown = sorted(set(args.kinds) - set(KINDS))
    if unknown:
        raise AuthPickerError("which-kind", f"unknown kind {unknown[0]!r}: use claude or codex")
    app = _app(args)
    text = badge.line(app, args.kinds or list(KINDS))
    if text:
        out(text)
    return 0


def _cmd_stamp(args: argparse.Namespace) -> int:
    badge.stamp(_app(args))
    return 0


def _status_kind(app: App, kind: str) -> None:
    backend = app.backends[kind]
    try:
        backend.check_supported()
        live = backend.read_live()
    except Unsupported as exc:
        if exc.code.endswith("-absent"):
            return
        out(f"{TITLES[kind]}: unsupported here: {exc.message}")
        return
    except AuthPickerError as exc:
        out(f"{TITLES[kind]}: cannot read the live login: {exc.message}")
        live = None
    else:
        if live is None:
            out(f"{TITLES[kind]}: logged out")
        else:
            saved = app.profiles.by_fingerprint(kind, live.fingerprint)
            name = saved.label if saved else "unsaved"
            out(f"{TITLES[kind]}: {name} ({live.identity.describe()})")
            expected = app.switcher.expected_fingerprint(kind)
            if expected and expected != live.fingerprint:
                out("  note: logged in outside auth-picker since the last switch")
    for profile in app.profiles.of_kind(kind):
        mark = "●" if live and live.fingerprint == profile.fingerprint else " "
        out(
            f"  {mark} {profile.label:<20} {profile.identity.describe()}  "
            f"(used {_ago(profile.last_used_at)})"
        )
    if app.store.get(f"undo:{kind}") is not None:
        out(f"  undo available: {kind}")
    for rescue in app.journals.rescues(kind):
        out(f"  ! {rescue.reason}: run `rescue` to review ({rescue.rid})")


def _cmd_status(args: argparse.Namespace) -> int:
    app = App.load(args.config, strict=False)
    out(f"auth-picker {__version__}")
    if app.config_error:
        out(f"config error, other commands will refuse to run: {app.config_error}")
    for kind in KINDS:
        _status_kind(app, kind)
    for orphan in app.profiles.orphans():
        out(f"note: unreferenced saved secret {orphan} (left by an interrupted save)")
    return 0


def _cmd_import_legacy(args: argparse.Namespace) -> int:
    app = _app(args)
    source = args.source or migrate.default_legacy_dir()
    candidates = migrate.plan(source, app.profiles)
    if not candidates:
        out(f"no saved logins found under {source}")
        return 0
    imported = migrate.apply(candidates, app.profiles) if args.apply else []
    for c in candidates:
        if c.importable and c.snapshot is not None:
            status = "imported" if args.apply else "ready"
            status += f" ({c.snapshot.identity.describe()})"
        else:
            status = c.problem or "skipped"
        out(f"{c.kind:<7} {c.label:<24} {status}")
        for issue in c.issues:
            if not issue.hard:
                out(f"{'':<32} note: {issue.message}")
    if not args.apply:
        out("nothing imported yet; run again with --apply to import the ready ones")
        return 0
    out(f"imported {len(imported)} of {len(candidates)}")
    left = migrate.leftovers(source)
    if left:
        out("the old plugin's plaintext copies are still on disk, untouched:")
        for path in left:
            out(f"  {path}")
        out("delete them once each imported profile has switched in successfully")
    return 0


# -- parser -------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="auth-picker",
        description="Switch Claude Code and Codex logins in herdr, without losing them.",
    )
    parser.add_argument("--version", action="version", version=f"auth-picker {__version__}")
    parser.add_argument(
        "--debug", action="store_true", help="show a (redacted) traceback on internal errors"
    )
    parser.add_argument("--config", help="settings file (default: the plugin config dir)")
    commands = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    def add(name: str, handler: Handler, help: str) -> argparse.ArgumentParser:
        sub = commands.add_parser(name, help=help)
        sub.set_defaults(handler=handler)
        return sub

    def kind(sub: argparse.ArgumentParser, required: bool = False) -> None:
        sub.add_argument("kind", choices=KINDS, nargs=None if required else "?")

    add("status", _cmd_status, "show what is logged in, saved, and needs attention")
    sub = add("save", _cmd_save, "save the live login(s) as a profile")
    kind(sub)
    sub.add_argument("--name", help="what to call it (default: from the account)")
    sub = add("switch", _cmd_switch, "switch to a saved login")
    kind(sub, required=True)
    sub.add_argument("name")
    sub.add_argument("--force", action="store_true", help="switch even if a renewal may be due")
    for name, handler, text in (
        ("next", _cmd_next, "switch to the next saved login"),
        ("undo", _cmd_undo, "switch back to the login before the last switch"),
    ):
        sub = add(name, handler, text)
        kind(sub)
        sub.add_argument("--force", action="store_true", help="switch even if a renewal may be due")
    sub = add("sync", _cmd_sync, "update the live login's saved copy")
    kind(sub)
    sub = add("rename", _cmd_rename, "rename a profile")
    kind(sub, required=True)
    sub.add_argument("name")
    sub.add_argument("new_name")
    sub = add("delete", _cmd_delete, "delete a profile (dry run without --yes)")
    kind(sub, required=True)
    sub.add_argument("name")
    sub.add_argument("--yes", action="store_true")
    sub = add("rescue", _cmd_rescue, "review or clear a stopped switch")
    sub.add_argument("--clear", metavar="ID")
    sub.add_argument("--yes", action="store_true")
    add("recover", _cmd_recover, "finish or undo an interrupted switch (startup hook)")
    add("stamp", _cmd_stamp, "refresh the account badge on agent panes")
    sub = add("badge", _cmd_badge, "print the account badge (for a tab bar)")
    sub.add_argument("kinds", nargs="*", metavar="KIND", help="claude and/or codex (default: both)")
    sub = add(
        "import-legacy",
        _cmd_import_legacy,
        f"import saved logins from {migrate.LEGACY_ID} (dry run by default)",
    )
    sub.add_argument("--from", dest="source", help="the old plugin's state directory")
    sub.add_argument("--apply", action="store_true", help="import, rather than only report")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    handler: Handler = args.handler
    try:
        return handler(args)
    except AuthPickerError as exc:
        err(f"auth-picker: {exc.message}")
        if herdr.invoked_by_herdr() and args.command in ("next", "undo", "save", "switch"):
            herdr.notify(f"auth-picker: {args.command} failed", exc.message)
        return exc.exit_code
    except KeyboardInterrupt:
        return EXIT_INTERRUPTED
    except Exception as exc:  # noqa: BLE001 - last line of defence; details only with --debug
        if args.debug:
            err(traceback.format_exc())
        else:
            err(
                f"auth-picker: internal error ({type(exc).__name__}); "
                "rerun with --debug for details"
            )
        return EXIT_INTERNAL
