"""Per-session slots (docs/design.md §14; I1, I8)."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from auth_picker.backends.claude import ClaudeSlot, FileCredential
from auth_picker.profiles import Profile
from auth_picker.slots import Slot, SlotError, Slots
from tests.fakes import claude_blob
from tests.test_switch import World


class Clock:
    def __init__(self) -> None:
        self.now = 1_000_000.0

    def __call__(self) -> float:
        return self.now


def file_slot(directory: str) -> ClaudeSlot:
    return ClaudeSlot(directory, store=FileCredential(str(Path(directory) / ".credentials.json")))


@pytest.fixture
def world(tmp_path: Path) -> World:
    w = World(tmp_path)
    w.log_in("alice")
    w.save("A", "alice")
    w.save("B", "bob")
    w.save("C", "carol")
    return w


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def using() -> dict[str, list[int]]:
    """slot directory -> pids, as the process scan would find them."""
    return {}


@pytest.fixture
def movers() -> set[int]:
    """Pids that are alive, as far as a slot's mover is concerned."""
    return {os.getpid()}


@pytest.fixture
def slots(world: World, clock: Clock, using: dict[str, list[int]], movers: set[int]) -> Slots:
    made = Slots(
        world.switcher,
        users=lambda dirs: {d: using.get(d, []) for d in dirs},
        clock=clock,
        make_slot=file_slot,
        alive=lambda pid: pid in movers,
    )
    world.switcher.slots = made
    return made


def profile(world: World, label: str) -> Profile:
    return world.profiles.find("claude", label)


def slot_file(slots: Slots, p: Profile) -> Path:
    return Path(slots.directory(p.id)) / ".credentials.json"


def renew_in_slot(slots: Slots, p: Profile, who: str, generation: int, **oauth: object) -> None:
    """What Claude does when a session in the slot renews its login."""
    blob = claude_blob(who, generation)
    blob["claudeAiOauth"].update(oauth)
    slot_file(slots, p).write_text(json.dumps(blob))


def test_lending_copies_only_the_account_keys(world: World, slots: Slots) -> None:
    b = profile(world, "B")
    directory = slots.lend(b)
    held = json.loads(slot_file(slots, b).read_text())
    assert set(held) == {"claudeAiOauth", "trustedDeviceToken"}
    assert held["claudeAiOauth"]["refreshToken"] == "sk-ant-ort01-bob-refresh-1"
    assert directory == slots.directory(b.id)
    assert slots.get(b.id) == Slot(b.id, "lent", slots.clock(), os.getpid())
    assert world.who() == "alice@example.com"  # the main store is untouched


def test_the_main_account_is_never_lent(world: World, slots: Slots) -> None:
    with pytest.raises(SlotError, match="main account"):
        slots.lend(profile(world, "A"))
    assert slots.all() == []


def test_the_main_store_cannot_take_an_account_a_session_holds(
    world: World, slots: Slots, using: dict[str, list[int]]
) -> None:
    b = profile(world, "B")
    slots.lend(b)
    slots.release(b.id)
    using[slots.directory(b.id)] = [4242]
    with pytest.raises(SlotError, match="in use by 1 pinned session"):
        world.switcher.switch("claude", "B")
    assert world.who() == "alice@example.com"
    with pytest.raises(SlotError, match="in use"):
        world.switcher.delete(b)


def test_a_session_that_is_starting_counts_as_using_its_slot(world: World, slots: Slots) -> None:
    slots.lend(profile(world, "B"))  # no process yet, but lent just now
    with pytest.raises(SlotError, match="starting"):
        world.switcher.switch("claude", "B")


def test_an_idle_slot_is_returned_first_and_its_newer_login_is_used(
    world: World, slots: Slots
) -> None:
    b = profile(world, "B")
    slots.lend(b)
    renew_in_slot(slots, b, "bob", 2)
    slots.release(b.id)
    world.switcher.switch("claude", "B")
    assert world.who() == "bob@example.com"
    live = json.loads((world.home / ".claude" / ".credentials.json").read_text())
    assert live["claudeAiOauth"]["refreshToken"] == "sk-ant-ort01-bob-refresh-2"
    assert slots.all() == []
    assert not Path(slots.directory(b.id)).exists()


def test_returning_keeps_the_previous_login_for_revert(world: World, slots: Slots) -> None:
    b = profile(world, "B")
    slots.lend(b)
    renew_in_slot(slots, b, "bob", 2)
    slots.release(b.id)
    assert "closed" in (slots.give_back(b.id) or "")
    secret, _ = world.profiles.secret(profile(world, "B"))
    assert b"refresh-2" in secret.reveal()
    world.switcher.revert(profile(world, "B"))
    secret, _ = world.profiles.secret(profile(world, "B"))
    assert b"refresh-1" in secret.reveal()


def test_a_slot_holding_another_profiles_login_is_never_saved_under_this_one(
    world: World, slots: Slots
) -> None:
    b = profile(world, "B")
    slots.lend(b)
    renew_in_slot(slots, b, "carol", 1)  # carol's saved tokens, in bob's slot
    slots.release(b.id)
    with pytest.raises(SlotError, match="held C's login"):
        world.switcher.switch("claude", "B")
    secret, _ = world.profiles.secret(profile(world, "B"))
    assert b"bob-refresh-1" in secret.reveal()  # B untouched (T5)
    assert world.journals.rescues("claude") == []  # C already holds that login
    assert slots.all() == []


def test_a_renewal_that_changes_the_plan_is_kept(world: World, slots: Slots) -> None:
    b = profile(world, "B")
    slots.lend(b)
    renew_in_slot(slots, b, "bob", 2, subscriptionType="pro", rateLimitTier="other")
    slots.release(b.id)
    assert "closed" in (slots.give_back(b.id) or "")
    secret, _ = world.profiles.secret(profile(world, "B"))
    assert b"bob-refresh-2" in secret.reveal()
    assert world.journals.rescues("claude") == []


def test_returning_runs_again_after_a_crash_that_left_no_directory(
    world: World, slots: Slots
) -> None:
    b = profile(world, "B")
    slots.lend(b)
    slots.release(b.id)
    slot_file(slots, b).unlink()
    Path(slots.directory(b.id)).rmdir()  # gone, but still in the index
    assert slots.tidy()
    assert slots.all() == []


def test_a_login_claude_gave_up_on_leaves_the_profile_alone(world: World, slots: Slots) -> None:
    b = profile(world, "B")
    slots.lend(b)
    renew_in_slot(slots, b, "bob", 2, refreshToken="")  # a failed renewal blanks it
    slots.release(b.id)
    assert "no working login" in (slots.give_back(b.id) or "")
    secret, _ = world.profiles.secret(profile(world, "B"))
    assert b"bob-refresh-1" in secret.reveal()
    assert slots.all() == []


def test_a_crash_while_lending_is_tidied_without_touching_the_profile(
    world: World, slots: Slots, movers: set[int], monkeypatch: pytest.MonkeyPatch
) -> None:
    b = profile(world, "B")

    def crash_after_write(self: ClaudeSlot, credentials: dict[str, object]) -> None:
        self.store.write(json.dumps(credentials).encode(), None)
        raise KeyboardInterrupt

    monkeypatch.setattr(ClaudeSlot, "write", crash_after_write)
    with pytest.raises(KeyboardInterrupt):
        slots.lend(b)
    assert slot_file(slots, b).exists()  # a copy of B's login, outside its profile
    movers.clear()  # the process that was lending is gone
    assert len(slots.tidy()) == 1
    assert slots.all() == []
    assert not slot_file(slots, b).exists()
    secret, _ = world.profiles.secret(profile(world, "B"))
    assert b"bob-refresh-1" in secret.reveal()


def test_next_skips_an_account_a_session_holds(
    world: World, slots: Slots, using: dict[str, list[int]]
) -> None:
    b = profile(world, "B")
    slots.lend(b)
    slots.release(b.id)
    using[slots.directory(b.id)] = [4242]
    assert world.switcher.next("claude").label == "C"


def test_a_damaged_index_stops_everything_rather_than_guessing(world: World, slots: Slots) -> None:
    Path(slots.index_path).write_text('{"slots": [{"profile_id": "../../etc"}]}')
    with pytest.raises(SlotError, match="damaged"):
        world.switcher.switch("claude", "B")
