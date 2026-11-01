"""The switch transaction under failure (docs/design.md sections 5-8; I1, I5)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import auth_picker.backends.claude as claude_module
import auth_picker.fsutil
from auth_picker import procscan
from auth_picker.backends.base import Snapshot
from auth_picker.backends.claude import ClaudeBackend
from auth_picker.errors import LockTimeout
from auth_picker.journal import Journal, JournalStore
from auth_picker.profiles import Profiles
from auth_picker.redact import Sensitive
from auth_picker.secretstore import FileStore
from auth_picker.switch import NeedsConfirmation, Switcher, SwitchError
from tests.fakes import (
    claude_blob,
    claude_secret,
    codex_auth,
    make_backends,
    write_claude_config,
)


class World:
    """A fake machine: Claude and Codex homes, a secret store, a switcher."""

    def __init__(self, root: Path, running: int = 0) -> None:
        self.root = root
        self.home = root / "home"
        backends = make_backends(root)
        self.profiles = Profiles(str(root / "state"), FileStore(str(root / "secrets")), backends)
        self.journals = JournalStore(str(root / "state"), self.profiles.store)
        self.switcher = Switcher(
            self.profiles,
            self.journals,
            lock_timeout=0.3,
            scan=lambda _kind: procscan.Sessions(running=running),
            store_lock_path=lambda sid: str(root / "locks" / f"{abs(hash(sid))}.lock"),
        )

    @property
    def claude(self) -> ClaudeBackend:
        backend = self.profiles.backends["claude"]
        assert isinstance(backend, ClaudeBackend)
        return backend

    def log_in(self, who: str, generation: int = 1, **machine: Any) -> None:
        creds = self.home / ".claude" / ".credentials.json"
        creds.write_text(json.dumps(claude_blob(who, generation, **machine)))
        write_claude_config(self.home / ".claude.json", who)

    def live(self) -> Snapshot:
        snap = self.claude.read_live()
        assert snap is not None
        return snap

    def save(self, label: str, who: str, generation: int = 1) -> None:
        snap = self.claude.parse_secret(Sensitive(claude_secret(who, generation)))
        self.profiles.create(label, snap)

    def who(self) -> str | None:
        return self.live().identity.email

    def tx_file(self) -> Path:
        return self.root / "state" / "tx" / "claude.json"


@pytest.fixture
def world(tmp_path: Path) -> World:
    w = World(tmp_path)
    w.log_in("alice")
    w.save("A", "alice")
    w.save("B", "bob")
    return w


def test_switch_moves_the_login_and_keeps_undo(world: World) -> None:
    outcome = world.switcher.switch("claude", "B")
    assert outcome.status == "switched"
    assert world.who() == "bob@example.com"
    assert not world.tx_file().exists()
    assert (
        world.profiles.store.get("undo:claude")
        == world.claude.parse_secret(Sensitive(claude_secret("alice"))).secret
    )

    world.switcher.undo("claude")
    assert world.who() == "alice@example.com"


def test_the_outgoing_login_is_saved_as_rotated(world: World) -> None:
    world.log_in("alice", generation=2)  # the CLI renewed alice's token since she was saved
    world.switcher.switch("claude", "B")
    a = world.profiles.find("claude", "A")
    secret, _ = world.profiles.secret(a)
    assert b"refresh-2" in secret.reveal()
    assert world.profiles.store.get(a.prev_key) is not None


def test_already_on_changes_nothing(world: World) -> None:
    assert world.switcher.switch("claude", "A").status == "already"
    assert not (world.root / "state" / "expected-claude.json").exists()


def test_an_unsaved_live_login_is_autosaved(world: World) -> None:
    world.log_in("carol")
    outcome = world.switcher.switch("claude", "B")
    assert "autosaved carol@example.com" in outcome.notes[0]
    assert world.profiles.find("claude", "autosaved carol@example.com")


def test_an_expired_saved_login_is_refused(world: World) -> None:
    blob = claude_blob("dave")
    blob["claudeAiOauth"]["refreshTokenExpiresAt"] = 1000
    secret = json.loads(claude_secret("dave"))
    secret["credentials"] = blob
    world.profiles.create("D", world.claude.parse_secret(Sensitive(json.dumps(secret).encode())))
    with pytest.raises(SwitchError, match="expired"):
        world.switcher.switch("claude", "D")
    assert world.who() == "alice@example.com"


def test_tokens_under_the_wrong_identity_stop_everything(world: World) -> None:
    creds = world.home / ".claude" / ".credentials.json"
    creds.write_text(json.dumps(claude_blob("bob")))  # bob's tokens, alice's identity
    before = creds.read_bytes()
    with pytest.raises(SwitchError, match="holds B's tokens"):
        world.switcher.switch("claude", "B")
    assert creds.read_bytes() == before
    (rescue,) = world.journals.rescues("claude")
    assert world.profiles.store.get(rescue.kept[0]["key"]) is not None
    with pytest.raises(SwitchError, match="unresolved"):
        world.switcher.switch("claude", "B")


def test_a_renewal_before_the_write_restarts_and_keeps_the_newest_token(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = ClaudeBackend.install
    calls: list[int] = []

    def renew_then_install(self: ClaudeBackend, *args: Any) -> None:
        if not calls:  # Claude renews alice's token right before our first write
            (world.home / ".claude" / ".credentials.json").write_text(
                json.dumps(claude_blob("alice", 3))
            )
        calls.append(1)
        real(self, *args)

    monkeypatch.setattr(ClaudeBackend, "install", renew_then_install)
    assert world.switcher.switch("claude", "B").status == "switched"
    assert len(calls) == 2
    secret, _ = world.profiles.secret(world.profiles.find("claude", "A"))
    assert b"refresh-3" in secret.reveal()


def test_a_failure_halfway_puts_the_previous_login_back(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = auth_picker.fsutil.write_foreign
    failed: list[str] = []

    def fail_identity_once(path: str, *args: Any, **kwargs: Any) -> Any:
        if path.endswith(".claude.json") and not failed:
            failed.append(path)
            raise OSError("disk full")
        return real(path, *args, **kwargs)

    monkeypatch.setattr(claude_module, "write_foreign", fail_identity_once)
    with pytest.raises(OSError, match="disk full"):
        world.switcher.switch("claude", "B")
    assert world.who() == "alice@example.com"
    assert b"alice" in (world.home / ".claude" / ".credentials.json").read_bytes()
    assert not world.tx_file().exists()
    assert world.journals.rescues() == []


def _crashed_switch(world: World) -> None:
    """Leave a journal as a switch to B killed mid-install would."""
    live = world.live()
    target = world.claude.parse_secret(Sensitive(claude_secret("bob")))
    journal = Journal(
        txid="crashed",
        kind="claude",
        phase="installing",
        target_label="B",
        target_fingerprint=target.fingerprint,
        target_components=world.claude.components(target),
        pre_fingerprint=live.fingerprint,
        pre_components=world.claude.components(live),
    )
    world.journals.begin(journal, live.secret)


def test_recovery_undoes_a_half_applied_switch(world: World) -> None:
    _crashed_switch(world)
    (world.home / ".claude" / ".credentials.json").write_text(json.dumps(claude_blob("bob")))
    assert world.switcher.recover("claude") == "aborted"
    assert b"alice" in (world.home / ".claude" / ".credentials.json").read_bytes()
    assert not world.tx_file().exists()


def test_recovery_completes_a_finished_switch(world: World) -> None:
    _crashed_switch(world)
    world.log_in("bob")
    assert world.switcher.recover("claude") == "committed"
    assert world.profiles.store.get("undo:claude") is not None


def test_recovery_keeps_everything_when_someone_else_wrote(world: World) -> None:
    _crashed_switch(world)
    world.log_in("carol")  # neither alice nor bob: an outside writer
    assert world.switcher.recover("claude") == "rescued"
    (rescue,) = world.journals.rescues("claude")
    kept = [world.profiles.store.get(entry["key"]) for entry in rescue.kept]
    assert [b"alice" in k.reveal() for k in kept if k] == [True, False]
    assert world.who() == "carol@example.com"  # left as found


def test_a_busy_claude_lock_changes_nothing(world: World) -> None:
    (world.home / ".claude" / ".oauth_refresh.lock").mkdir()
    with pytest.raises(LockTimeout, match="Claude Code is refreshing"):
        world.switcher.switch("claude", "B")
    assert world.who() == "alice@example.com"
    assert not world.tx_file().exists()


def test_next_cycles_through_profiles(world: World) -> None:
    assert world.switcher.next("claude").label == "B"
    assert world.switcher.next("claude").label == "A"


def _codex_world(tmp_path: Path, running: int) -> World:
    w = World(tmp_path, running=running)
    codex = w.profiles.backends["codex"]
    auth = w.home / ".codex" / "auth.json"
    auth.write_text(json.dumps(codex_auth("alice", expires_in=120)))
    live = codex.read_live()
    assert live is not None
    w.profiles.create("A", live)
    other = tmp_path / "other"
    other.mkdir()
    (other / "auth.json").write_text(json.dumps(codex_auth("bob")))
    w.profiles.create(
        "B",
        codex.parse_secret(
            Sensitive(
                json.dumps({"schema": 1, "kind": "codex", "auth": codex_auth("bob")}).encode()
            )
        ),
    )
    return w


def test_codex_near_renewal_with_sessions_running_asks_first(tmp_path: Path) -> None:
    w = _codex_world(tmp_path, running=1)
    with pytest.raises(NeedsConfirmation):
        w.switcher.switch("codex", "B")
    assert w.switcher.switch("codex", "B", force=True).status == "switched"


def test_codex_near_renewal_with_nothing_running_just_switches(tmp_path: Path) -> None:
    w = _codex_world(tmp_path, running=0)
    assert w.switcher.switch("codex", "B").status == "switched"
