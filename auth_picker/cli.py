"""Command-line interface: argv in, exit code out."""

from __future__ import annotations

import argparse
from collections.abc import Callable, Sequence

from auth_picker import __version__

Handler = Callable[[argparse.Namespace], int]


def _cmd_status(_args: argparse.Namespace) -> int:
    print(f"auth-picker {__version__}: under construction, nothing to report yet")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="auth-picker",
        description="Switch Claude Code and Codex logins in herdr, without losing them.",
    )
    parser.add_argument("--version", action="version", version=f"auth-picker {__version__}")
    commands = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")
    status = commands.add_parser("status", help="show what is logged in and what is saved")
    status.set_defaults(handler=_cmd_status)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    handler: Handler = args.handler
    return handler(args)
