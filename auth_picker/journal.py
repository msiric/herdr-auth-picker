"""Switch journals and rescues: what lets a crash or an outside writer be survived.

A journal records one switch in flight: the transaction id, its phase, and,
per component, the hash of what was there before and of what we were
writing. The previous login itself is a secret, ``tx:<id>:pre``.

A rescue records a state the plugin could not explain. Every generation it
saw is kept in the secret store as ``rescue:<id>:<n>``, and nothing is
switched for that kind until the user clears it (design §6).
"""

from __future__ import annotations

import json
import os
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any

from auth_picker.fsutil import read_private, remove_private, secure_dir, write_private
from auth_picker.redact import Sensitive
from auth_picker.secretstore.base import SecretStore

MAX_BYTES = 256 * 1024


@dataclass
class Journal:
    txid: str
    kind: str
    phase: str  # "begun" | "installing"
    target_label: str
    target_fingerprint: str
    target_components: dict[str, str]
    pre_fingerprint: str | None  # None: nobody was logged in
    pre_components: dict[str, str] = field(default_factory=dict)
    started_at: float = field(default_factory=time.time)
    # Which credential store this switch wrote to ("<kind>-<hash of store id>").
    store: str = ""

    @property
    def pre_key(self) -> str:
        return f"tx:{self.txid}:pre"


@dataclass
class Rescue:
    rid: str
    kind: str
    reason: str
    created_at: float
    kept: list[dict[str, Any]]  # [{"key", "what", "describe", "fingerprint"}]
    # "interrupted" (a switch stopped part-way) or "contaminated" (one account's
    # tokens under another's identity: never to be adopted into a profile).
    cause: str = "interrupted"


class JournalStore:
    def __init__(self, state_dir: str, store: SecretStore) -> None:
        self.state_dir = state_dir
        self.store = store
        self.tx_dir = os.path.join(state_dir, "tx")
        self.rescue_dir = os.path.join(state_dir, "rescue")

    # -- journals ----------------------------------------------------------

    def _tx_path(self, store: str) -> str:
        return os.path.join(self.tx_dir, f"{store}.json")

    def begin(self, journal: Journal, pre: Sensitive | None) -> None:
        if pre is not None:
            self.store.put(journal.pre_key, pre)  # secret first
        self.write(journal)

    def write(self, journal: Journal) -> None:
        secure_dir(self.tx_dir)
        write_private(self._tx_path(journal.store), json.dumps(asdict(journal)).encode())

    def current(self, store: str) -> Journal | None:
        """The switch in flight for one credential store, if any."""
        data = read_private(self._tx_path(store), MAX_BYTES)
        return Journal(**json.loads(data)) if data is not None else None

    def pre_secret(self, journal: Journal) -> Sensitive | None:
        return self.store.get(journal.pre_key) if journal.pre_fingerprint else None

    def close(self, journal: Journal) -> None:
        remove_private(self._tx_path(journal.store))  # journal first, then its secret
        self.store.delete(journal.pre_key)

    # -- rescues -----------------------------------------------------------

    def open_rescue(
        self,
        kind: str,
        reason: str,
        kept: list[tuple[str, Sensitive, str, str | None]],
        cause: str = "interrupted",
    ) -> Rescue:
        """Keep every given generation (what, secret, describe, fingerprint) and record why."""
        rid = uuid.uuid4().hex[:12]
        entries = []
        for n, (what, secret, describe, fingerprint) in enumerate(kept):
            key = f"rescue:{rid}:{n}"
            self.store.put(key, secret)
            entries.append(
                {"key": key, "what": what, "describe": describe, "fingerprint": fingerprint}
            )
        rescue = Rescue(rid, kind, reason, time.time(), entries, cause)
        secure_dir(self.rescue_dir)
        write_private(
            os.path.join(self.rescue_dir, f"{rid}.json"), json.dumps(asdict(rescue)).encode()
        )
        return rescue

    def rescues(self, kind: str | None = None) -> list[Rescue]:
        try:
            names = sorted(os.listdir(self.rescue_dir))
        except FileNotFoundError:
            return []
        found = []
        for name in names:
            data = read_private(os.path.join(self.rescue_dir, name), MAX_BYTES)
            if data is not None and name.endswith(".json"):
                rescue = Rescue(**json.loads(data))
                if kind is None or rescue.kind == kind:
                    found.append(rescue)
        return found

    def clear_rescue(self, rescue: Rescue) -> None:
        remove_private(os.path.join(self.rescue_dir, f"{rescue.rid}.json"))
        for entry in rescue.kept:
            self.store.delete(entry["key"])
