"""Command-line interface: argv in, exit code out.

This is the only place that writes to stdout/stderr, and all of it passes
through ``redact``: herdr keeps both streams in its plugin logs.
"""

from __future__ import annotations

import argparse
import sys
import traceback
from collections.abc import Callable, Sequence

from auth_picker import __version__, migrate
from auth_picker.app import App
from auth_picker.errors import AuthPickerError
from auth_picker.redact import redact

Handler = Callable[[argparse.Namespace], int]

EXIT_INTERNAL = 70
EXIT_INTERRUPTED = 130


def out(text: str) -> None:
    sys.stdout.write(redact(text) + "\n")


def err(text: str) -> None:
    sys.stderr.write(redact(text.rstrip("\n")) + "\n")


def _cmd_status(_args: argparse.Namespace) -> int:
    out(f"auth-picker {__version__}: under construction, nothing to report yet")
    return 0


def _cmd_import_legacy(args: argparse.Namespace) -> int:
    app = App.load(args.config)
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
    status = commands.add_parser("status", help="show what is logged in and what is saved")
    status.set_defaults(handler=_cmd_status)
    legacy = commands.add_parser(
        "import-legacy", help=f"import saved logins from {migrate.LEGACY_ID} (dry run by default)"
    )
    legacy.add_argument("--from", dest="source", help="the old plugin's state directory")
    legacy.add_argument("--apply", action="store_true", help="import, rather than only report")
    legacy.set_defaults(handler=_cmd_import_legacy)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    handler: Handler = args.handler
    try:
        return handler(args)
    except AuthPickerError as exc:
        err(f"auth-picker: {exc.message}")
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
