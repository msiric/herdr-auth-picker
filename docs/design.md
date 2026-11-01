# Design — msiric.auth-picker v1

Status: draft for review (phase 0). Read with [`threat-model.md`](threat-model.md).

## 0. Decisions (fixed)

| | decision |
|-|----------|
| Language | Python ≥ 3.11, standard library only at runtime (dev tools allowed). |
| Profile storage | macOS: one login-keychain item per profile. Linux: 0600 files in a 0700 dir. Metadata index on disk holds no secrets. |
| Pre-switch check | Local validation plus `undo`. No network. |
| Usage | Opt-in. Read live only for the logged-in account, using its current access token, and never refresh. Parked accounts show their last reading with its age. |
| Codex | v1, with `cli_auth_credentials_store = "file"` (the default) only. |
| Repo / id | `msiric/herdr-auth-picker`, plugin id `msiric.auth-picker`. |

## 1. Invariants (every one has tests)

Some writers are outside our control: running CLIs refresh and rewrite their
stores whenever they like. So the invariants are scoped to what a plugin can
guarantee. Where it can't, it must **detect the problem and stop**, never guess.

- **I1 — Never destroy the chain head.** The *chain head* is the most recent
  credential generation we have observed for an account. We never overwrite or
  delete it without first durably keeping it elsewhere (its profile, or a
  transaction or rescue record). A stale generation sitting on disk does not
  satisfy this.
- **I2 — No token endpoint.** The plugin never sends a refresh token anywhere,
  and its source contains no token-endpoint URL or OAuth client id.
- **I3 — Secrets stay in the secret stores.** They never appear in argv, a
  child's environment, temp files, logs, stdout/stderr, notifications or
  exception messages. On-disk state may hold SHA-256 hashes of tokens; it never
  holds the tokens.
- **I4 — Foreign files are patched, not rewritten.** A file we don't own is
  modified only by patching named keys of an object we fully parsed. The write
  goes through a version check and preserves the mode and symlink target.
  Rollback patches only the keys we wrote, and only while they still hold the
  value we wrote.
- **I5 — A switch is all-or-nothing, or stops.** Against our own writers (we
  hold the machine-wide store lock), a switch is applied and verified, or
  restored exactly. When an outside writer interferes, the switch stops in a
  *rescue* state that keeps every observed generation, and asks the user.
  Recovery never automatically commits or restores a state it can't explain.
- **I6 — Profiles update only with evidence.** A profile is updated from the
  live store only under the lock, from a consistent snapshot, when identities
  match, when the contamination check passes, and with no unresolved write-back
  anomaly for that kind. Its previous generation is kept, so a wrong update can
  be reverted.
- **I7 — Restricted network use.** The plugin makes only HTTPS GETs to
  allowlisted hosts, carrying only the live account's unexpired access token.
  No redirects, and responses are capped in size and time.

## 2. Architecture

```
herdr-plugin.toml
auth_picker.py              entry: version check, sys.path = own dir, run cli (python3 -I)
auth_picker/
  cli.py                    argv → command; single top-level error handler + redaction
  config.py                 typed, validated config (tomllib); fails closed on invalid
  errors.py                 AuthPickerError(code, msg) — never carries secret data
  redact.py                 output filter: sk-ant-*, JWTs, long hex/base64 → [REDACTED]
  fsutil.py                 durable atomic write, safe read, secure dir, foreign-file CAS
  proc.py                   run(argv, input=bytes) via pipes; timeout kills process group
  lock.py                   plugin flock (re-entrant, bounded wait) + foreign lock helpers
  secretstore/              SecretStore protocol: get/put/delete(key) → bytes
    keychain.py             `security -i` + `-X <hex>` on stdin; reads via pipe
    filestore.py            0600 files under 0700 dir (Linux)
  backends/                 Backend protocol (below)
    claude.py  codex.py
  profiles.py               metadata index + secret refs; CRUD under lock
  journal.py                switch journal + crash recovery
  switch.py                 the transaction; undo
  procscan.py               running-session detection (key presence only)
  usage.py                  opt-in live-only reader + non-secret cache
  herdr.py                  herdr CLI wrapper (agents, metadata, notify, panes)
  badge.py                  read-only badge text (no network, no writes, no spawns)
  ui/picker.py              curses picker
  migrate.py                one-way import from rcosteira.account-switch
tests/  pyproject.toml  .github/workflows/ci.yml  SECURITY.md  README.md
```

`python3 -I` (isolated mode) ignores `PYTHONPATH`, `PYTHONSTARTUP` and user
site-packages, so nothing in the environment can shadow our modules or the
standard library.

### Backend protocol

```python
class Backend(Protocol):
    kind: str
    def detect(self) -> Supported | Unsupported(reason)   # fail closed
    def read_live(self) -> LiveSnapshot | None              # consistent snapshot
    def validate(self, secret: Secret) -> list[Issue]       # hard / soft issues
    def identity(self, secret: Secret) -> Identity
    def install(self, secret: Secret, expect: Version) -> None   # CAS against expect
    def restore(self, preimage: Preimage) -> None
```

`LiveSnapshot` = account-scoped secret + identity + `Version` (what was read,
for the compare-and-swap).

## 3. Stores (verified facts in §10)

### Claude Code

- **Credential store.**
  - macOS: login-keychain item. Service: `Claude Code-credentials`, plus
    `-<sha256(NFC config dir)[:8]>` when `CLAUDE_CONFIG_DIR` is set. Account:
    `$USER`, or `claude-code-user` if `$USER` doesn't match
    `^[a-zA-Z0-9._-]+$`.
  - Linux: `<config dir>/.credentials.json`.
- **Blob keys:** explicit allowlists, no default bucket.
  - `ACCOUNT_KEYS = {claudeAiOauth, trustedDeviceToken,
    trustedDeviceEnrolledAfterRefusalAtMs}`. The device token is enrolled with
    the account's own credentials, and cleared for accounts that aren't
    subscribers (V2). If that's ever wrong, Claude re-enrolls after a 403.
  - `MACHINE_KEYS = {mcpOAuth}`. These are **preserved from the live blob on
    install**. The original plugin swapped the whole blob, clobbering MCP
    logins (audit F27).
  - Any key in neither set → fail closed: "unsupported Claude credential layout
    (key `X`)". A new key then needs one reviewed line, not a guess.
- **Identity file.** Resolved as Claude resolves it:
  `<config dir>/.config.json` if that is a non-empty regular file, otherwise
  `$CLAUDE_CONFIG_DIR/.claude.json` or `~/.claude.json`. It holds
  `oauthAccount` (`accountUuid`, `organizationUuid`, `emailAddress`,
  `organizationName`, …).
- **Claude's own locks** (2.1.309, V1): directory locks, where taking the lock
  means `mkdir`, the holder keeps the directory's mtime fresh, and releasing
  means `rmdir`. A switch takes all of them, all-or-nothing:
  - `<config dir>/.oauth_refresh.lock` (stale 60 s), plus the legacy
    `<realpath(config dir)>.lock`. Claude holds these while refreshing, and
    re-reads the store after taking them.
  - `<config dir>/.storage-write.lock` (stale 15 s). Claude holds it for every
    credential-store write.
  - `<identity file>.lock` (stale 10 s). Claude holds it for every config
    write.
- **Fingerprint.** `sha256("claude|" + accountUuid + "|" + organizationUuid)`.
  This tells apart one user with two orgs (audit F12).
- **Install order:**
  1. Write the credential.
  2. Patch `oauthAccount`.
  3. On macOS, if `<config dir>/.credentials.json` exists, bump its mtime.
     Done last, so running sessions re-read only once both stores agree.
- **Fail closed** if:
  - the computed Keychain item is absent while `oauthAccount` is present;
  - `CLAUDE_CODE_OAUTH_TOKEN` is set in our own environment (the user is
    pinned; report it);
  - the blob or identity shape is unknown.

### Codex

- **Store.** `$CODEX_HOME/auth.json`, default `~/.codex`. The whole object is
  account-scoped, and unknown fields are kept verbatim. **We never write
  `last_refresh`** (audit F7).
- **Supported modes.** Only when `$CODEX_HOME/config.toml` has no
  `cli_auth_credentials_store` or has `"file"`. `keyring`, `auto` and
  `ephemeral` are refused with an explanation.
- **Locking.** Codex 0.163.0 takes **no lock** and rewrites `auth.json`
  **in place** (truncate + write; V3). A read can therefore see a partial file,
  so a parse failure means "being written", and we retry it, never treat it as
  logged out. Newer Codex takes an `flock` on `<resolved auth.json>.lock`. We
  take it too (harmless where unused), plus a version check on (mtime_ns, size,
  ino). With no lock on 0.163.0, the renewal guard (§8) applies to Codex.
- **Identity.** From the `id_token` claims under
  `https://api.openai.com/auth`: `chatgpt_account_id`, plus `chatgpt_user_id`
  or `sub`. `tokens.account_id` must equal `chatgpt_account_id`, or the snapshot
  is treated as inconsistent.
- **Fingerprint.** `sha256("codex|" + account_id + "|" + user_id)`.
- **API-key mode** (`OPENAI_API_KEY` without tokens): unsupported in v1.

## 4. Data model

State: `$HERDR_PLUGIN_STATE_DIR` (0700, owner verified).

```
index.json            {"schema":1,"profiles":[{id, kind, label, identity, fingerprint,
                       created_at, updated_at, last_used_at, refresh_expires_at,
                       cred_hash}]}
tx/<txid>.json        transaction journal (non-secret): kind, phase, target_id,
                       hashes of pre-image and installed value per component
rescue/<rid>.json     unresolved anomaly (non-secret): what was observed, secret refs
expected-<kind>.json  {fingerprint, cred_hash, installed_at}: write-back detection
usage-cache.json      {profile_id: {read_at, windows, error, retry_after}} (non-secret)
audit.jsonl           append-only events, no secrets, rotated at 1 MiB
lock                  state lock (our index, journal, cache)
```

The **machine-wide store lock** lives outside any herdr state dir, so two
installs, sessions or the tab bar can't interleave:
`~/.local/state/msiric.auth-picker/locks/<sha256(store identity)>.lock`. The
store identity is the canonical credential path or Keychain service+account,
plus the identity file path. Lock order is always store lock, then state lock.

Secret-store keys (Keychain service `msiric.auth-picker`, or file names):

```
profile:<id>          current generation of a profile
profile:<id>:prev     previous generation (one level, for reverting a bad update)
tx:<txid>:pre         immutable pre-image of a transaction ({"absent": true} if logged out)
undo:<kind>           user undo; written only after a switch commits
rescue:<rid>:<n>      generations kept when an anomaly stopped a switch
```

- `cred_hash` = sha256 of the account-scoped credential.
- `id` is a random UUID. Labels live only in the index, so a **rename is a
  single index write** (audit F13), and no path is built from user or file data
  (audit F19).
- **One profile per fingerprint**, enforced in the index.
- Index writes are durable and atomic: `mkstemp` in the same dir, `fchmod 600`,
  write, `fsync`, `rename`, then `fsync` the dir.
- Order is always **secret first, index second**. A crash leaves an orphan
  secret (harmless, swept by `status --repair` after confirmation), never an
  index entry pointing at nothing.

## 5. Switch transaction

```
switch(kind, target_id):
  with store_lock(kind), state_lock():
    refuse if any unresolved rescue/tx exists for kind      # §6
    backend.detect()                                        # fail closed
    target = index[target_id]; secret = store.get(profile:target_id)
    validate(secret); assert identity(secret).fingerprint == target.fingerprint
    loop (max 3):
      live = backend.read_live()                            # consistent snapshot, or None
      if live:
        integrity_checks(live)                              # §7 (also before "already on")
        renewal_guard(live)                                 # §8: refuse if about to renew
        if live.fingerprint == target.fingerprint: return "already on"
        out = index.by_fingerprint(live.fingerprint) or new autosaved profile
        update_profile(out, live)                           # keeps :prev; secret first
      tx = journal.begin(kind, target_id, pre=live or ABSENT)   # writes tx:<id>:pre, fsync
      if backend.changed_since(live): journal.abort(tx); continue   # restart, never roll back
      try:
        backend.install(merge(live, secret), expect=live.version)  # per-component, journaled
        after = backend.read_live()
        verify after.fingerprint == target.fingerprint and after.cred_hash == hash(secret)
      except Conflict:     # an outside writer interfered mid-install
        rescue(tx, observed=[pre, current]); raise "stopped, see status"
      except BaseException:
        backend.undo_own_writes(tx)   # restores only components still equal to our write
        journal.close(tx, "rolled_back"); raise
      journal.close(tx, "committed")
      store.put(undo:kind, tx.pre); expected.write(kind, target.fingerprint, hash(secret))
      index.mark_used(target); audit("switched"); break
  after locks: stamp badges; warnings = procscan(kind); notify(label only)
```

- **`undo kind`** switches to `undo:<kind>` through the same transaction. That
  includes "logged out" when the pre-image was absent; then it removes the
  store, and only with confirmation.
- **`next`** cycles profiles by `created_at`.
- **Merge.** For Claude, the installed blob is the live `MACHINE_KEYS` plus the
  target's `ACCOUNT_KEYS`. For Codex, the target object as-is.

## 6. Crash recovery

The journal records the phase and, for each component, the hash of the
pre-image and of the value we were installing. Recovery runs in the
`[[startup]]` hook and before every mutating command, under the store lock:

| journal phase | live store, per component | action |
|---------------|---------------------------|--------|
| `begun` (nothing written) | equals the pre-image | close as aborted |
| `installing` | every component equals what we installed | close as committed (write `undo`, `expected`) |
| `installing` | every component equals the pre-image | close as aborted |
| `installing` | components equal to our install mixed with ones equal to the pre-image | finish restoring: write the pre-image only to the components holding our value; verify; close |
| any | any component equal to **neither** hash | **rescue**: keep the current value and the pre-image as `rescue:<rid>:*`, stop, notify |

A rescue is resolved only by the user, in `status`: they choose which
generation each profile keeps, from the observed account details. Nothing
auto-commits or auto-restores a value the plugin didn't write.

## 7. Identity and sync rules (audit F4/F5)

- **Consistent snapshot (Claude).** Read the Keychain, then `.claude.json`, then
  the Keychain again. Both credential reads must be equal and the file version
  unchanged. Up to 3 retries, otherwise "store is changing — try again".
- **Integrity checks.** They run on every live read used for a decision,
  *before* any "already on" shortcut:
  - **Contamination.** The live refresh token, or `cred_hash`, equals a
    generation stored for a profile with a *different* fingerprint (including
    `:prev`).
  - **Write-back.** The live `cred_hash` differs from `expected` while the
    fingerprint is unchanged. That is normal CLI rotation *unless* the token
    matches another profile; it is only flagged if it does.
  - **Identity drift.** The live fingerprint differs from `expected`, and no
    switch or save by us explains it. That is normal after a manual `/login`:
    we report it, and no profile is touched until the user saves or syncs.

  Contamination stops everything and opens a rescue. Drift only disables the
  automatic profile update for that kind until the user confirms.
- **Updating a profile from live** (switch-away, `save`, the explicit `sync`
  action) requires all of I6. It moves the old generation to `:prev` first.
- Never on UI ticks, `list`, `badge` or usage reads.
- **Limit, stated plainly.** Claude's tokens are opaque, so nothing offline
  binds a credential to an account. These checks catch every case where a token
  we've already seen turns up under the wrong identity. A brand-new token under
  the wrong identity (an old process rotating after a switch) can't be told
  apart from normal rotation. That residual risk is why `:prev` exists and why
  the renewal guard (§8) shrinks the window.

## 8. Concurrency

| resource | protection |
|----------|------------|
| a CLI's live store, across all plugin installs and processes | machine-wide **store lock** (§4) |
| our state | state lock, taken after the store lock |
| Codex `auth.json` | flock on `auth.json.lock` (Codex's own commit lock, V3) plus a version check. Codex's writes are atomic, so we can't lose its update |
| `~/.claude.json` | Claude's lock if it has one (V1). Otherwise a version check on (mtime_ns, size, ino) immediately before rename, with up to 3 retries. The residual window is microseconds; rollback patches only `oauthAccount`, and only while it still equals our value |
| Claude credential store and identity file | **Claude's own locks** (§3), taken all-or-nothing: try each in a fixed order (refresh, legacy, storage-write, identity); if one is busy, release everything and retry with jitter until the timeout. No partial holding, so no deadlock with Claude. A lock is broken only if its mtime is older than twice its stale period (a crashed holder), as Claude itself would. Held for well under stale/2. The protocol is pinned to tested Claude versions; on an untested version the steps below apply too, and `status` warns. |
| Claude Keychain item, fallback | (1) **Renewal guard:** if `claude` processes are running *and* the live access token is within 10 min of `expiresAt` or past it, those sessions may renew at any moment. The switch then asks for confirmation ("a running session may renew this login now; switching could strand the new token — continue?"), and `next`/`switch` refuse unless `--force`. With no running sessions there's no race, so no guard. (2) Re-read right before writing; any change restarts the switch. (3) Read back after writing; a mismatch opens a rescue. |
| running CLIs writing an old account back | `expected-<kind>.json` holds `cred_hash`. Picker and `status` compare it with the live store (the badge doesn't read the Keychain). A mismatch that matches another profile's generation opens a rescue; any other mismatch counts as normal rotation. |

## 9. Other components

- **Network (`usage.py`, the only module importing `urllib`):**
  - one opener: default TLS context, a redirect handler that raises, and
    `ProxyHandler({})`;
  - allowlist: `api.anthropic.com`, `chatgpt.com`, GET only;
  - User-Agent `msiric-auth-picker/<version>`;
  - 5 s timeout, 64 KiB cap;
  - a live, unexpired access token only. A 401 means "expired, the CLI will
    renew" and is not retried;
  - TTL 300 s (minimum 120 s), honours `Retry-After`;
  - single-flight via a non-blocking flock. If another process is reading, the
    cache is used.
- **procscan.** Linux: look for the bytes `\0CLAUDE_CODE_OAUTH_TOKEN=` in
  `/proc/<pid>/environ` and keep no values. macOS: `ps -E` through a pipe, check
  key presence, drop the buffer. It reports pinned sessions, and sessions
  started before the switch (which may still hold the old account in memory).
- **herdr.**
  - Actions: `open`, `next`, `save`, `undo`, `status`, `sync`, `usage`,
    `import-legacy`.
  - Pane: `picker`.
  - `[[startup]]`: `recover` and stamp badges.
  - No config editing; the README carries the snippet.
  - No detached processes, no symlink in the state dir.
- **Badge.** Claude identity comes from `oauthAccount`, so the badge needs no
  Keychain read. The badge shows `!` when a rescue is open. Codex identity is decoded from `auth.json` and nothing is
  kept. Usage comes from the cache. The badge does no network calls, writes or
  spawns.
- **Config.** `$HERDR_PLUGIN_CONFIG_DIR/config.toml` (`--config PATH` for the
  tab bar). Unknown keys or invalid values are an error shown by `status`, and
  actions that depend on them refuse to run. No env-var overrides.
  - Badge template: literal replacement of `{glyph} {label} {kind}`, never
    `str.format`.
  - Keys: `notify`, `notify_identity` (off: notifications show labels, not
    emails), `badge`, `badge_format`, `glyph`, `lock_timeout_s`,
    `[usage] enabled, ttl_s`.
- **Observability.**
  - Errors: `AuthPickerError(code, message)`, messages built only from labels
    and codes.
  - One top-level handler, `--debug` for tracebacks.
  - All output passes through `redact()`.
  - `audit.jsonl`: ts, action, kind, from/to label, result, code.
- **Migration.** `import-legacy` reads `rcosteira.account-switch` profiles. It
  validates each one, flags an expired or likely-spent refresh token, imports
  into the secret store and index, and never deletes the source. It then prints
  the exact legacy paths to delete once the user is satisfied.

## 10. Verified facts (2026-11-01, macOS 26.7.1)

| fact | source |
|------|--------|
| `security add-generic-password -U … -w` with stdin piped **stores an empty password and exits 0** (retype mismatch) | reproduced with a dummy item |
| `security -i` + `add-generic-password -U -s … -a … -X <hex>` on stdin: exact round-trip (quotes, unicode), updates existing items, prints nothing, non-zero exit on error | reproduced with a dummy item |
| urllib forwards all headers but content-* (incl. `Authorization`) on 301/302/303/307/308 GET redirects, any host | CPython 3.14 `HTTPRedirectHandler.redirect_request` |
| Claude Code 2.1.309 Keychain service and account naming as in §3 | Claude 2.1.309 binary (keychain-naming function) |
| Claude 2.1.309 lock files and stale periods as in §3; refresh re-reads the store after locking; global config is `.config.json` when present | Claude 2.1.309 binary (lock and refresh functions) |
| `trustedDeviceToken` is enrolled with the account's credentials and cleared for non-subscribers | Claude 2.1.309 binary (trusted-device functions) |
| Codex 0.163.0 writes `auth.json` in place (`truncate`, `write_all`), with no lock; no `json.lock` in the binary | `openai/codex` @ `rust-v0.163.0` `login/src/auth/storage.rs`; installed binary |
| Keychain blob keys: `claudeAiOauth{accessToken, refreshToken, expiresAt(ms), refreshTokenExpiresAt, scopes, subscriptionType, subscriptionTypeSource, rateLimitTier}`, `trustedDeviceToken` | live item, structure only |
| `oauthAccount` includes `accountUuid`, `organizationUuid`; Claude merges profile fetches into it; writes config via temp file + rename, refusing symlinks, preserving mode | live file (keys only), 2.1.309 binary |
| Claude tracks `lastCredentialsMtimeMs` and caches Keychain reads for 30 s | 2.1.309 binary |
| Codex `auth.json`: `auth_mode, OPENAI_API_KEY, tokens{id_token, access_token, refresh_token, account_id}, last_refresh` (RFC3339 with `Z`); `last_refresh: Option<DateTime<Utc>>` | live file (structure), `openai/codex` `login/src/auth/storage.rs` |
| Codex store mode enum `file` (default) / `keyring` / `auto` / `ephemeral` | `openai/codex` `config/src/types.rs` |
| Codex serializes credential commits with an flock on `<auth.json>.lock`, and has compare-and-save | `openai/codex` `login/src/auth/storage_commit.rs` (main) |
| Anthropic: developers "may not collect, store, or intermediate Claude.ai credentials or session tokens" | code.claude.com legal-and-compliance |
| `security -i` runs commands longer than about 4,090 characters in pieces, storing a truncated value; the `-w` prompt silently keeps only 128 characters | reproduced on throwaway and dummy items (found by the end-to-end run) |

## 11. To verify in later phases

| id | question | phase |
|----|----------|-------|
| V1 | ~~Does Claude lock `~/.claude.json`?~~ **Yes**, plus a refresh lock and a storage-write lock (§3). | 4 ✔ |
| V2 | ~~`trustedDeviceToken` scope?~~ **Account-scoped** (§3). | 4 ✔ |
| V3 | ~~Codex 0.163.0 lock?~~ **No.** It writes in place, without a lock (§3). | 4 ✔ |
| V4 | Does a running Codex follow an `auth.json` swap, and does it write back after refresh? **Not verified** (no second Codex account). | 10 |
| V5 | ~~Does a running Claude session follow a Keychain swap?~~ **Partly ✔** (2026-11-01): a running 2.1.303 session's `/status` account and account-scoped settings followed a switch and an undo, with `.credentials.json` absent. Billing to the new account not confirmed by a request. | 10 |
| V6 | ~~herdr working directory and state dir?~~ The working directory is the plugin root; state is `~/.local/state/herdr/plugins/<id>` (0755, which we tighten), and config is `~/.config/herdr/plugins/config/<id>`. | 7 ✔ |
| V7 | ~~Do the usage endpoints accept an honest User-Agent?~~ **Yes** (2026-11-01): both answered with usage for `msiric-auth-picker/0.1.0`. | 10 ✔ |
| V8 | Linux paths/behaviour: CI only, as there is no Linux machine here. | 4/10 |

## 12. Testing

- **Unit:** identity, merge, validation, redaction, config, badge template.
- **Fault injection:** named checkpoints in `switch` / `install`
  (`after_outgoing_persist`, `after_tx_begin`, `after_credential_write`,
  `after_identity_write`, …). In-process exceptions plus subprocess `os._exit`
  crashes, then `recover()`; assert I1/I5 and that no chain head was lost.
- **Outside-writer simulation:** a fake CLI that rotates the live generation,
  or writes an old account back, at every checkpoint. Assert the switch
  restarts, rolls back only its own writes, or opens a rescue, and never
  overwrites an unseen generation without keeping it.
- **Concurrency:** multiprocess tests for the plugin lock, a simulated CLI
  writer racing the version check, and the Codex lock.
- **Property tests (hypothesis, dev-only):** random sequences of
  save/switch/rename/delete/undo/crash/external-login against fakes; the
  invariants hold after every step.
- **Static guards:**
  - no token-endpoint hosts, client ids or `grant_type` in the source;
  - `urllib` imported only by `usage.py`;
  - no `-w` passed to `security`;
  - `proc.run` takes secrets only via `input=`.
- **Keychain integration (opt-in, macOS):** dummy services prefixed
  `auth-picker-test-` only. The harness refuses any other service.
- **Manual end-to-end checklist** with real accounts (phase 10), run by you.
- **CI:** GitHub Actions on macOS and Ubuntu, Python 3.11 and 3.13: ruff,
  mypy --strict, pytest.

## 13. Phases and exit criteria

| phase | deliverable | done when |
|-------|-------------|-----------|
| 1 | Skeleton, tooling, CI, manifest, entry point | CI green on an empty test suite; `python3 -I auth_picker.py --help` |
| 2 | fsutil, proc, lock, redact, errors, config | unit and concurrency tests; static guards in place |
| 3 | Secret stores (Keychain, file) | Keychain integration tests pass on dummy items |
| 4 | Claude + Codex backends; resolve V1–V3 | read/validate/install/restore tests against fakes and temp homes |
| 5 | Profile index, CRUD, migration | rename/delete crash tests; legacy import tested on fixture data |
| 6 | Switch, journal, recovery, undo, procscan; resolve V4–V5 | fault-injection and property suites green |
| 7 | herdr integration, badge; resolve V6 | actions work in a linked dev install |
| 8 | Picker UI | manual run-through |
| 9 | Usage (opt-in); resolve V7 | network guards tested with a local fake server |
| 10 | Docs, SECURITY.md, manual E2E with real accounts, tag v1.0.0 | checklist signed off by you |
