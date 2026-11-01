"""Source-level guards for invariants that are easiest to break by accident.

See docs/design.md §1 (I2, I3, I7) and §12.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from tests.conftest import ROOT

SOURCES = sorted([ROOT / "main.py", *(ROOT / "auth_picker").rglob("*.py")])

# I2: the plugin never renews tokens itself, so nothing token-endpoint shaped
# belongs in the source.
FORBIDDEN_TEXT = (
    "/oauth/token",
    "grant_type",
    "client_id",
    "platform.claude.com",
    "auth.openai.com",
    "9d1c250a-e61b-44d9-88ed-5944d1962f5e",  # Claude Code's OAuth client id
    "app_EMoamEEZ73f0CkXaXp7hrann",  # Codex's OAuth client id
)

# Only these modules may import these. Everything else goes through them.
CONFINED_IMPORTS = {
    "subprocess": {"auth_picker/proc.py"},
    "urllib": {"auth_picker/usage.py"},
    "http": {"auth_picker/usage.py"},
}

FORBIDDEN_CALLS = {"eval", "exec", "os.system", "os.popen", "pickle.loads", "pickle.load"}


def _rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def _dotted(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{_dotted(node.value)}.{node.attr}"
    return ""


@pytest.mark.parametrize("path", SOURCES, ids=_rel)
def test_no_token_endpoint_material(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    assert not [marker for marker in FORBIDDEN_TEXT if marker in text]


@pytest.mark.parametrize("path", SOURCES, ids=_rel)
def test_confined_imports_and_calls(path: Path) -> None:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    problems: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import | ast.ImportFrom):
            names = [a.name for a in node.names] if isinstance(node, ast.Import) else [node.module or ""]
            for name in names:
                root = name.split(".")[0]
                allowed = CONFINED_IMPORTS.get(root)
                if allowed is not None and _rel(path) not in allowed:
                    problems.append(f"line {node.lineno}: imports {name}")
        elif isinstance(node, ast.Call):
            name = _dotted(node.func)
            if name in FORBIDDEN_CALLS:
                problems.append(f"line {node.lineno}: calls {name}")
            for keyword in node.keywords:
                if keyword.arg == "shell":
                    problems.append(f"line {node.lineno}: passes shell=")
    assert not problems
