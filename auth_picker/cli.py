"""Command-line interface: argv in, exit code out.

This is the only place that writes to stdout/stderr, and all of it passes
through ``redact``: herdr keeps both streams in its plugin logs.
"""

from __future__ import annotations

import argparse
import sys
import traceback
from collections.abc import Callable, Sequence

from auth_picker import __version__
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="auth-picker",
        description="Switch Claude Code and Codex logins in herdr, without losing them.",
    )
    parser.add_argument("--version", action="version", version=f"auth-picker {__version__}")
    parser.add_argument(
        "--debug", action="store_true", help="show a (redacted) traceback on internal errors"
    )
    commands = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")
    status = commands.add_parser("status", help="show what is logged in and what is saved")
    status.set_defaults(handler=_cmd_status)
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
