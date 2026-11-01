# End-to-end checklist (real accounts)

Unit and integration tests cover the logic against fake homes and throwaway
keychains. These steps cover what only real CLIs can show. Run them in order.
Each says what it touches. Nothing here contacts a provider except step 7,
and only with your go-ahead.

Before you start: note which account each CLI is on (`status`). Every switch
keeps the previous login for `undo`, and nothing here deletes a login.

Run commands from the plugin directory as `python3 -I main.py <command>`.

## 1. Read-only baseline

- `status`: both CLIs show their live account as `unsaved`.
- The picker (`open` action): both kinds listed. Quit with `q`.

Touches: nothing. Status reads the Claude Keychain item and `auth.json`.

## 2. Save the current logins

- `save`
- `status`: both live accounts are now saved and marked `●`.
- `security find-generic-password -s msiric.auth-picker -a profile:<id>`
  finds each item. Look for the item; don't print the password.

Touches: creates two Keychain items and the profile index.

## 3. A second Claude account

- In a Claude pane: `/login` with the other account. `save claude`.
- `status`: two Claude profiles; the new one live.

Touches: your Claude login (via Claude itself).

## 4. Switch Claude with no session running (V5, part 1)

- Quit every `claude` session. Action `next`.
- `claude auth status --json` in a new pane shows the other account;
  `status` agrees; the badge changes.
- `undo`, then check the same way.

Touches: the Claude Keychain item and `oauthAccount` in `~/.claude.json`.
`~/.claude.json` keeps everything else: compare `projects` before and after.

## 5. Switch Claude with a session running (V5, part 2)

- Start `claude` in a pane, ask it something. Action `next`.
- In the same session, ask again, then `/status`: which account answered?
- Record the result in docs/design.md §11 (V5).

## 6. Codex (V4)

- If you have a second Codex account: `codex login` with it, `save codex`.
- Same as steps 4 and 5 with `codex`. Note whether a running `codex` follows
  the switch, and whether the old account is written back afterwards (`status`
  would say "logged in outside auth-picker").

## 7. Usage (V7): asks for your go-ahead first

- This sends the live account's access token to the provider's usage endpoint
  with an honest `msiric-auth-picker` User-Agent: the terms-of-service grey
  zone in the README.
- If you agree: set `[usage] enabled = true`, run `usage`, and record whether
  each provider answered or refused.

## 8. Recovery drill (optional)

- `mkdir ~/.claude/.oauth_refresh.lock`, action `next`: refused with "Claude
  Code is refreshing", nothing changed. `rmdir` it afterwards.

## Sign-off

When 1–6 pass (7 optional), record the results in docs/design.md §11, update
the README status, and tag `v1.0.0`.

## Results (2026-11-01, macOS 26.7.1, Claude Code 2.1.309 CLI with 2.1.303 sessions running, Codex 0.163.0)

| step | result |
|------|--------|
| 1 baseline | pass |
| 2 save | pass, after two fixes it found: Keychain writes over about 4 KB were truncated by `security -i` (now split into parts, and oversize writes refused); a damaged item could not be deleted. The read-back check meant nothing was lost. |
| 3 second Claude account | pass; the out-of-band `/login` was reported as such |
| 4 and 5 Claude switch and undo | pass: a fresh `claude` and `status` agreed each time; `~/.claude.json` kept all 106 other keys; no lock left behind. Five sessions were running throughout (step 4's "none running" was not possible). It also found the session scan counting processes that only mentioned Claude's npm package. |
| V5 | partly verified: a running session's `/status` account and account-scoped settings followed the switch and the undo. Billing not confirmed by a request. |
| 6 / V4 Codex | not run: no second Codex account |
| 7 / V7 usage | pass: both providers answered the honest User-Agent; it found a 30-day window labelled "weekly" (fixed) |
| 8 recovery drill | skipped on purpose with five live sessions; covered by tests |

Tagged `v1.0.0-rc.1`. Promote to `v1.0.0` once V4 and V5 billing are confirmed.

## Follow-up results (2026-11-01, later the same evening)

| check | result |
|-------|--------|
| V5 billing | **pass**: in a running 2.1.303 session, a switch to an account out of usage made the next message hit its weekly limit; after `undo` the same session answered |
| second Codex account | added safely with `CODEX_HOME=/tmp/… codex login` and `save codex --from`, because `codex login` revokes its home's existing login (found in Codex's source); the live login was untouched |
| V4 Codex | **no immediate follow**: the CLI (0.166.0) talks to a background `codex app-server` that keeps its login in memory, new sessions included. After `codex app-server daemon restart`, a new session used the new account. No write-back. A switch now says so. |
| independent review | four issues fixed: per-install Keychain namespace (with migration), store-keyed journals and undo, logins made outside saved with `:prev` plus `revert` and `rescue --adopt`, and Claude's fail-closed check for a credential not where its config says |
| migration on this Mac | 22 items moved to the per-install service, all profiles read back |
