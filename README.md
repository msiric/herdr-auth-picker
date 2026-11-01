# herdr-auth-picker

Switch the logged-in Claude Code or Codex account from inside
[herdr](https://herdr.dev), without losing logins along the way.

> **Status: under construction. Not usable yet.** The design is in
> [`docs/design.md`](docs/design.md), and the threat model is in
> [`docs/threat-model.md`](docs/threat-model.md).

## Development

Python 3.11 or newer. No runtime dependencies. Dev tools are pinned in
`requirements-dev.txt`:

```sh
python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
.venv/bin/ruff check . && .venv/bin/ruff format --check .
.venv/bin/mypy
.venv/bin/pytest
```
