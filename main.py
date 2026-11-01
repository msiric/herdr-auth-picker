#!/usr/bin/env python3
"""herdr entry point: ``python3 -I main.py <command>``."""

import os
import sys

if sys.version_info < (3, 11):  # noqa: UP036 - this guard is the point: say why, not a SyntaxError
    sys.stderr.write(
        "auth-picker: Python 3.11 or newer is required (found %d.%d)\n" % sys.version_info[:2]
    )
    sys.exit(2)

if not sys.flags.isolated:
    # Run without -I (e.g. from a hand-written tab-bar command): start again
    # isolated, before importing anything the environment could shadow.
    os.execv(sys.executable, [sys.executable, "-I", os.path.realpath(__file__), *sys.argv[1:]])  # noqa: S606

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))

from auth_picker.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
