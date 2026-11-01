# herdr-auth-picker

Switch which Claude Code or Codex account is logged in, from inside
[herdr](https://herdr.dev), without logging out and back in, and without
losing a login along the way.

> **Status: 1.0.0.** Verified end to end with real Claude and Codex accounts,
> including running sessions, and independently reviewed. Results:
> [`docs/e2e-checklist.md`](docs/e2e-checklist.md).

It replaces [`rcosteira79/herdr-account-switch`](https://github.com/rcosteira79/herdr-account-switch),
which this project audited and rebuilt. The audit found no malicious code, but
did find defects that could blank a login, wipe `~/.claude.json`, or spend a
refresh token for good. Each of those is now covered by design and by tests. The
design is in [`docs/design.md`](docs/design.md), and the threats it answers are
in [`docs/threat-model.md`](docs/threat-model.md).

## What it guarantees

- **The newest copy of a login is never destroyed.** Before anything is
  written, the login that is live now is saved: to its profile (keeping the
  generation before it), or as a new `autosaved …` profile.
- **A switch completes, or puts things back, or stops and asks.** Every switch
  is journaled. After a crash, the next run completes it or restores the
  previous login. Any state it can't explain is kept whole and reported, never
  guessed at.
- **It never renews a token.** No token endpoint, no OAuth client ids. Renewal
  is left to the CLIs themselves.
- **Secrets stay where they belong.** Saved logins are Keychain items on macOS
  and 0600 files on Linux. No secret is ever on a command line, in a log, in a
  notification, or written anywhere but its own store. Atomic writes create
  their temporary file inside the destination's own directory.
- **It writes the CLIs' files the way they do.** It takes Claude Code's own
  locks, so no Claude process renews or saves mid-switch. In `~/.claude.json`
  it patches only `oauthAccount`, keeps your MCP logins, follows symlinks, and
  refuses a file that changed under it.
- **Usage display is opt-in.** It reads the logged-in account only, over HTTPS
  to the provider's own host, with no redirects or proxies.

## Requirements

- herdr ≥ 0.9.0, Python ≥ 3.11, macOS or Linux. No other dependencies.
- Tested with **Claude Code 2.1.309** and **Codex 0.163.0**. Codex must use
  file storage (`cli_auth_credentials_store = "file"`, the default).

## Install

From a local checkout (this repository is private, so this is the usual way):

```sh
herdr plugin link ~/Documents/herdr-auth-picker
```

From GitHub, pinned to a commit you have reviewed:

```sh
herdr plugin install msiric/herdr-auth-picker --ref <commit-sha>
```

Then save the logins you have:

```sh
herdr plugin action invoke msiric.auth-picker.save
```

Then add your other accounts:

- **Claude Code:** `/login` with the other account, then `save` again.
- **Codex: never `codex login` in your normal Codex home to add an account.**
  It revokes the login that home holds, even another account's, which would
  kill the saved one. Log in under a throwaway home and import from there:

  ```sh
  CODEX_HOME=/tmp/codex-second codex login     # sign in as the other account
  python3 -I main.py save codex --from /tmp/codex-second
  rm -rf /tmp/codex-second                      # it holds that login in plaintext
  ``` To bring over the old plugin's profiles, see
[Moving from herdr-account-switch](#moving-from-herdr-account-switch).

## Use

| from herdr | does |
|------------|------|
| action `open` | the picker: `enter` switch, `s` save, `r` rename, `x` delete, `u` undo, `q` quit |
| action `next` | switch the focused agent's kind to its next saved account |
| action `undo` | switch back to the account before the last switch |
| action `save` | save every login that is live now |
| action `sync` | update the live login's saved copy (after you `/login` again) |
| action `status` | what is live, what is saved, anything needing attention |

Keybindings (`~/.config/herdr/config.toml`, then `herdr server reload-config`):

```toml
[[keys.command]]
key = "prefix+a"
type = "plugin_action"
command = "msiric.auth-picker.next"
description = "next account"

[[keys.command]]
key = "prefix+shift+a"
type = "plugin_action"
command = "msiric.auth-picker.open"
description = "account picker"
```

Every action is also a command. `python3 -I main.py --help` lists them, and
`switch`, `rename`, `delete`, `rescue`, `usage` and `import-legacy` are
available only this way.

### The badge

To show the account on each agent row in herdr's sidebar, add the `$acct`
token. The plugin never edits your herdr config.

```toml
[ui.sidebar.agents]
rows = [["state_icon", "workspace", "tab", "$acct"], ["agent"]]
```

Or show it once, in the tab bar. Use the directory `herdr plugin list` reports:

```toml
[ui]
tab_bar_right = [
  { type = "command", command = "python3 -I /path/to/herdr-auth-picker/main.py badge", interval_seconds = 30, timeout_seconds = 5 },
]
```

The badge reads no secrets and makes no network calls: Claude's account comes
from its config file, not the Keychain. `name*` means a login no profile holds,
and `!` means something needs attention (see `status`).

## Settings

`$(herdr plugin config-dir msiric.auth-picker)/config.toml`. Unknown keys and
bad values are errors that `status` reports, never silently ignored.

| key | default | meaning |
|-----|---------|---------|
| `notify` | `true` | herdr notification when an action switches, saves or fails |
| `notify_identity` | `false` | include the email and plan in those notifications |
| `badge` | `true` | stamp `$acct` on agent panes |
| `badge_format` | `"{glyph} {label}"` | any of `{glyph}`, `{label}`, `{kind}`, `{usage}` |
| `glyph` | `"👤"` | the badge character |
| `lock_timeout_s` | `5` | how long to wait for another switch, or for Claude's own locks |
| `[usage] enabled` | `false` | read the logged-in account's usage from the provider |
| `[usage] ttl_s` | `300` | how often, at most, in seconds (minimum 120) |

## What it reads and writes

| | where |
|-|-------|
| Claude login | Keychain `Claude Code-credentials` (macOS) or `~/.claude/.credentials.json`; identity in `~/.claude.json` (`oauthAccount` only). `CLAUDE_CONFIG_DIR` is honoured as Claude honours it. |
| Claude's locks | `~/.claude/.oauth_refresh.lock`, `~/.claude.lock`, `~/.claude/.storage-write.lock`, `~/.claude.json.lock`, held only during a switch |
| Codex login | `$CODEX_HOME/auth.json` (default `~/.codex`), with `auth.json.lock` held while writing |
| saved logins | Keychain service `msiric.auth-picker.<install id>`, one per state directory (macOS); `<state dir>/secrets/` (Linux) |
| state, no secrets | `~/.local/state/herdr/plugins/msiric.auth-picker/`: profile index, switch journal, rescues, usage cache |
| switch lock | `~/.local/state/msiric.auth-picker/locks/` |

## When something needs attention

- **`status` shows `!` or a rescue.** A switch was interrupted in a way it
  couldn't explain, or one account's tokens turned up under another's name.
  Every login involved is kept. Run `rescue` to see them. When the login you
  want is live or saved, clear it with `rescue --clear ID --yes`. Until then,
  switching that kind is refused.
- **"may renew this login at any moment".** A running Codex session's token is
  about to expire, and Codex has no lock to stop it renewing mid-switch. Wait a
  minute, or pass `--force`.
- **A running session keeps using the old account.** If `CLAUDE_CODE_OAUTH_TOKEN`
  is set in that session's environment, it outranks any login on disk; unset it
  and restart the session.
- **"logged in outside auth-picker".** You used `/login` since the last switch.
  That newer login is saved to its profile when you switch away, and the copy
  before it is kept: `revert <kind> <name> --yes` swaps them back.
- **Codex still uses the old account after a switch.** Codex sessions talk to
  a background server that keeps its login in memory. Run
  `codex app-server daemon restart` (it interrupts running Codex work); a
  switch says when this applies.
- **A rescue holds the login you want.** `rescue --adopt ID --item N` saves it
  as a profile; then clear the rescue.

## Moving from herdr-account-switch

From the plugin's directory:

```sh
python3 -I main.py import-legacy            # shows what it would import
python3 -I main.py import-legacy --apply    # imports the ready ones
```

It never changes the old files. Once each imported profile has switched in
successfully, delete the old plugin's `profiles/`, `backups/` and `rotated/`
directories, which the import lists: they hold logins in plaintext.

## Limits

- Running Claude sessions follow a switch on their next request (verified).
  Running Codex sessions follow only once Codex's background server restarts.
- Credential layouts are the CLIs' private business. Unknown shapes are
  refused rather than guessed at, so a CLI update can require an update here.
- The usage endpoints are undocumented. Anthropic's terms say developers "may
  not collect, store, or intermediate Claude.ai credentials or session tokens";
  this tool does store your own tokens, on your own machine. Decide for
  yourself.

## Development

```sh
python3 -m venv .venv && .venv/bin/pip install --require-hashes -r requirements-dev.txt
.venv/bin/ruff check . && .venv/bin/ruff format --check . && .venv/bin/mypy && .venv/bin/pytest
```

Keychain tests use a throwaway keychain file, never your login keychain.
Usage tests run against a local HTTPS server.
