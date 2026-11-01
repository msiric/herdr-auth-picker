# Threat model

Status: draft for review (phase 0).

Scope: `msiric.auth-picker` v1. It switches which Claude Code or Codex account is
logged in on one machine, from inside herdr.

## 1. Assets

| id | asset | why it matters |
|----|-------|----------------|
| A1 | Refresh tokens (Claude `claudeAiOauth.refreshToken`, Codex `tokens.refresh_token`) | Long-lived account access. Claude records `refreshTokenExpiresAt`, and until then the token mints access tokens. Each refresh token works once: if it is spent and the reply is lost, the login is gone. |
| A2 | Access tokens | Hours of account access, with inference billed to the account. |
| A3 | **Availability of each login** | The most likely real loss. A destroyed refresh chain costs a browser login. For an account that is hard to re-authenticate (SSO, another device) it costs more. |
| A4 | Integrity of files we don't own: `~/.claude.json` (projects, MCP config, history), `$CODEX_HOME/auth.json`, herdr `config.toml` | Clobbering them destroys unrelated user state. |
| A5 | Account metadata (emails, org names, plan) | Mild privacy exposure. |
| A6 | Provider account standing | Behaviour that looks like a third-party client using subscription credentials risks enforcement. |

## 2. Trust boundaries and actors

| actor | trust | notes |
|-------|-------|-------|
| The user, same uid | trusted | Owns config and invokes actions. |
| Official CLIs (Claude Code, Codex) running as the user | trusted, **concurrent writers** | They refresh tokens and rewrite the stores at any moment, and hold tokens in memory. |
| herdr server | trusted | Runs our commands, **keeps our stdout/stderr in its plugin logs**, and shows notifications. |
| Other local users | untrusted | Can see process argv (`ps`). Cannot read 0600 files or the login keychain. |
| Same-uid malware, root | **out of scope** | Can read the login keychain via `security`, and our files. No plugin can defend against this, and the docs say so plainly. |
| Network | untrusted | TLS only, to an allowlist of first-party hosts. |
| Providers (Anthropic, OpenAI) | trusted for auth decisions; a risk for terms-of-service enforcement | They rotate and revoke tokens, rate-limit, and may restrict which clients can use credentials. |
| Data on disk (our index, config, foreign JSON) | validated input | May be malformed, hand-edited, partly written, or from an older version. |
| Plugin code updates | trusted only at a pinned commit | Install by SHA. No third-party dependencies. |

## 3. Threats → mitigations

| id | threat | mitigation (design ref) |
|----|--------|-------------------------|
| T1 | A secret is visible to other users through argv or `ps` | Secrets travel only on stdin pipes. Keychain writes use `security -i` with `-X <hex>` (verified). Secrets never go in argv or a child's environment. (D-SEC) |
| T2 | A secret is written to disk outside the secret store (temp files, subprocess output, backups, logs) | Pipes and `communicate()`, never temp files for subprocess I/O. Profiles live in the Keychain. No plaintext backups. Every output path goes through redaction. (D-SEC, D-OBS) |
| T3 | A crash, kill or power loss mid-operation loses or corrupts a login | Journaled switch with a pre-image, durable writes (`fsync` of file and directory), and recovery on the next start. (D-TXN) |
| T4 | A CLI rewrites its store at the same time (refresh, `/login`), or two plugin instances switch at once | A machine-wide store lock across plugin instances. Take Codex's `auth.json.lock`. A version check on every foreign write. Consistent-snapshot reads. A renewal guard. A change before writing restarts the switch; unexplained states become rescues, never guesses. (D-CONC, design §6, §8) |
| T5 | Live→profile sync cross-writes accounts (B's tokens under A's identity) | Sync only at controlled points, under the lock, from a consistent snapshot. Contamination and write-back checks against every known generation, run before any shortcut. The previous generation is kept for revert. (D-ID, design §7) |
| T6 | `~/.claude.json` gets clobbered | Patch only `oauthAccount`. Abort if the file doesn't parse; never write an object we didn't fully parse. Compare-and-swap on mtime, size and inode. Preserve the mode. Write through a symlink to its target. (D-FOREIGN) |
| T7 | Refresh tokens get spent (lost replies, reuse detection) | **The plugin never calls a token endpoint.** Renewal is the CLIs' job. A test that greps the source enforces this. (D-NET) |
| T8 | A token leaks via a redirect, a proxy or plain HTTP | GET only, https only, host allowlist, redirects disabled, response size cap. (D-NET) |
| T9 | Terms-of-service / enforcement exposure | No token endpoint, no use of the CLIs' client ids, honest User-Agent. Usage reads are opt-in, live account only, rate-limited and cache-first. The remaining risk is documented. (D-NET) |
| T10 | A dead, wrong or malformed snapshot gets installed | Local structural and identity checks before install. Refuse an expired refresh token. `undo`. (D-VAL) |
| T11 | The wrong store is targeted (`CLAUDE_CONFIG_DIR`, an unusual `$USER`, Codex keyring mode) | Compute the store exactly as the CLI does (verified for Claude 2.1.309), check the item exists, and refuse unsupported modes. (D-STORE) |
| T12 | Malformed or hostile local data (index, config, foreign JSON, herdr output) | Strict schema checks and size limits. Ids are never used as raw path components. (D-VAL) |
| T13 | Information leaks through herdr logs, notifications or tracebacks | Typed errors that carry no secret data, one top-level handler, a redaction filter. Notifications carry labels, not emails, by default. (D-OBS) |
| T14 | Orphaned background processes, or config that runs code from the mutable state dir | No detached processes. No symlink in the state dir that config executes. (D-HERDR) |
| T15 | Supply chain | Standard library only. Install pinned to a commit SHA. CI on every change. Signed tags later. |

## 4. Residual risks (accepted, documented)

- Same-uid malware can read every token, as it already can with the CLIs alone.
- A running CLI holds the old account's tokens in memory. It may keep billing the
  old account until it re-reads the store, and it may write the old account back
  after a refresh. We detect this and warn; we cannot prevent it.
- Claude's in-memory change detection (the mtime of `.credentials.json`) and its
  storage layout are private, and any CLI release can change them. We pin the
  tested versions and refuse unknown shapes.
- The usage endpoints are undocumented and may change or be restricted.
- Using a third-party tool to swap subscription logins is a policy grey zone, even
  without touching token endpoints.

## 5. Review log

- 2026-11-01: an independent review of design v0 raised 7 blocking issues: the
  Keychain race, ambiguous recovery, identity binding, the undo slot as
  transaction storage, the `.claude.json` check gap, the unknown-key merge, and
  the per-state-dir lock. All are addressed in design §1, §3–§8.
