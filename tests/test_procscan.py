from __future__ import annotations

import pytest

from auth_picker.procscan import kind_of


@pytest.mark.parametrize(
    ("argv0", "args", "kind"),
    [
        ("/Users/a/.local/bin/claude", "/Users/a/.local/bin/claude --resume", "claude"),
        ("/Users/a/.local/share/claude/versions/2.1.309", "x", "claude"),
        ("node", "node /usr/lib/node_modules/@anthropic-ai/claude-code/cli.js", "claude"),
        ("/opt/homebrew/bin/codex", "codex exec", "codex"),
        ("/Users/a/.codex/packages/app-server-daemon/releases/0.166.0/bin/codex", "", "codex"),
        ("/Applications/Claude.app/Contents/MacOS/Claude", "", None),
        ("/opt/homebrew/bin/codex-code-mode-host", "", None),
        ("/usr/bin/python3", "python3 claude.py", None),
        ("/usr/bin/grep", "grep @anthropic-ai/claude-code notes.txt", None),
    ],
)
def test_which_processes_count_as_sessions(argv0: str, args: str, kind: str | None) -> None:
    assert kind_of(argv0, args) == kind
