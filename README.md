# herdr-auth-picker

Switch which Claude Code or Codex account is logged in, from inside
[herdr](https://herdr.dev), without logging out and back in, and without
losing a login along the way.

> **Status: 1.3.0.** Verified end to end with real Claude and Codex accounts,
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

- herdr ≥ 0.9.1, Python ≥ 3.11 (found automatically, even when `python3` is
  Apple's 3.9), macOS or Linux. No other dependencies.
- Tested with **Claude Code 2.1.309** and **Codex 0.163.0**. Codex must use
  file storage (`cli_auth_credentials_store = "file"`, the default).

## Install

From GitHub, pinned to a release (read the code first: it handles your logins):

```sh
herdr plugin install msiric/herdr-auth-picker --ref v1.3.0
```

Or from a local checkout: `herdr plugin link /path/to/herdr-auth-picker`.

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
  bin/auth-picker save codex --from /tmp/codex-second
  rm -rf /tmp/codex-second                      # it holds that login in plaintext
  ``` To bring over the old plugin's profiles, see
[Moving from herdr-account-switch](#moving-from-herdr-account-switch).

## Use

herdr has no menu for plugin actions: you run them from keys you bind. Add
these to `~/.config/herdr/config.toml`, then `herdr server reload-config`.
`prefix` is `ctrl+b` unless you changed it, so `prefix+a` means ctrl+b, let go,
then a. `prefix+?` lists every binding.

```toml
[[keys.command]]
key = "prefix+a"
type = "plugin_action"
command = "msiric.auth-picker.open"
description = "accounts: picker"

[[keys.command]]
key = "prefix+shift+a"
type = "plugin_action"
command = "msiric.auth-picker.next"
description = "accounts: next"

[[keys.command]]
key = "prefix+u"
type = "plugin_action"
command = "msiric.auth-picker.undo"
description = "accounts: switch back"
```

| key | action | does |
|-----|--------|------|
| `prefix+a` | `open` | the picker: `j`/`k` move, `enter` switch, `s` save, `r` rename, `x` delete, `u` undo, `d` every usage window, `q` close |
| `prefix+shift+a` | `next` | switch the focused pane's tool (Claude or Codex) to its next saved account |
| `prefix+u` | `undo` | switch back to the account you were on before the last switch; press again to toggle back |

The other actions, `save` (save every login that is live now), `sync` (update
the live login's saved copy) and `status`, can be bound the same way, or run
from a shell: `herdr plugin action invoke msiric.auth-picker.save`.

Every action is also a command: `bin/auth-picker` in the plugin directory
finds a Python 3.11 or newer for you (set `AUTH_PICKER_PYTHON` to choose one).
`bin/auth-picker --help` lists them, and
`switch`, `rename`, `delete`, `rescue`, `usage` and `import-legacy` are
available only this way.

### The badge

The plugin puts two tokens on every Claude and Codex pane: `$acct` (the
account) and `$usage` (how much of it is used, when usage is on). herdr shows
a token only where a sidebar row names it. The plugin never edits your herdr
config, so add them yourself. Beside the agent's name, for Claude and Codex
panes only, so other agents keep their usual layout:

```toml
[ui.sidebar.agents.rows_by_agent]
claude = [["state_icon", "workspace", "tab"], ["agent", "$acct", "$usage"]]
codex = [["state_icon", "workspace", "tab"], ["agent", "$acct", "$usage"]]
```

and, in the plugin's `config.toml`, `badge_format = "{label}"` to drop the
glyph. Then `herdr server reload-config`. herdr puts a `·` between tokens:

```
● Documents · Real estate
claude · work · 42% 5h ↺2h10
```

With long profile names, or a narrow sidebar, give each token its own row
instead (`[["agent", "$usage"], ["$acct"]]`) or raise `ui.sidebar_width`.

`$usage` shows the window closest to stopping the account. An account stops
when *any* of its windows is full, so:

1. a full window wins (if several, the one that frees up last);
2. otherwise the account-wide window used most, so `37% wk ↺2d17h` when the
   weekly limit is further along than the five-hour one (`12% 5h`);
3. a per-model weekly limit (Claude's, e.g. `Fable`) counts only once full.

`42% 5h ↺2h10` reads: 42% of the five-hour window used, resetting in 2h10.
`wk` and `mo` are the weekly and monthly windows, and `~` marks a reading older
than twice `ttl_s`, or the last one taken while that account was live. To see
every window all the time, set `[usage] style = "both"` (`12%·5h 37%·wk`), or
use the `$usage_5h` and `$usage_wk` tokens, which always hold those two
windows. `d` in the picker and `bin/auth-picker usage` list every window,
per-model ones included.

Short profile names read best (`bin/auth-picker rename claude mario.example
work`); `badge_format = "{label}"` drops the glyph.

A new Claude or Codex pane gets its badge as soon as herdr detects the agent.
When an agent finishes a turn, the plugin re-reads that account's usage (at
most once per `ttl_s`, only if usage is on) and refreshes the badges. There is
no background process; herdr's agent events drive it.

Or show both accounts once, in the tab bar. It reads only the cache, never the
network or the Keychain:

```toml
[ui]
tab_bar_right = [
  { type = "command", command = "/path/to/herdr-auth-picker/bin/auth-picker badge", interval_seconds = 30, timeout_seconds = 5 },
]
```

With `badge_format = "{glyph} {label} {usage}"` it reads
`Claude 👤 work 42% · Codex 👤 work 3%`. `name*` means a login no profile
holds, and `!` means something needs attention (see `status`).

## Settings

`$(herdr plugin config-dir msiric.auth-picker)/config.toml`. Unknown keys and
bad values are errors that `status` reports, never silently ignored.

| key | default | meaning |
|-----|---------|---------|
| `notify` | `true` | herdr notification when an action switches, saves or fails |
| `notify_identity` | `false` | include the email and plan in those notifications |
| `badge` | `true` | stamp `$acct`, `$usage`, `$usage_5h` and `$usage_wk` on Claude and Codex panes |
| `badge_format` | `"{glyph} {label}"` | the `$acct` text, from `{glyph}`, `{label}`, `{kind}`, `{usage}` |
| `glyph` | `"👤"` | the badge character |
| `lock_timeout_s` | `5` | how long to wait for another switch, or for Claude's own locks |
| `codex_restart` | `"ask"` | after a Codex switch, restart Codex's background server: `ask` (the picker and a terminal ask; actions only tell you), `always`, or `never` |
| `[usage] enabled` | `false` | read the logged-in account's usage from the provider |
| `[usage] ttl_s` | `300` | how often, at most, in seconds (minimum 120) |
| `[usage] style` | `"binding"` | `$usage` shows the window closest to stopping the account, or `"both"` account-wide windows |

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
  a background server that keeps its login in memory, and Codex refuses to
  reload a different account on its own. Restarting it is the only way: the
  picker offers it (`codex_restart`), `--restart-codex` does it, and
  `codex app-server daemon restart` does it by hand. Open conversations are
  saved; a reply in progress is cut off. The restarted server inherits the
  environment of whatever restarted it.
- **A rescue holds the login you want.** `rescue --adopt ID --item N` saves it
  as a profile; then clear the rescue.

## Moving from herdr-account-switch

From the plugin's directory:

```sh
bin/auth-picker import-legacy            # shows what it would import
bin/auth-picker import-legacy --apply    # imports the ready ones
```

It never changes the old files. Once each imported profile has switched in
successfully, delete the old plugin's `profiles/`, `backups/` and `rotated/`
directories, which the import lists: they hold logins in plaintext.

## Limits

- Running Claude sessions follow a switch on their next request (verified).
  Running Codex sessions follow only once Codex's background server restarts,
  which the plugin offers to do right after the switch.
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

## License

MIT. See [`LICENSE`](LICENSE).
