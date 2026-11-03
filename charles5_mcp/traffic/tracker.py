"""Incremental view over repeated full-session exports.

Charles has no incremental API: every poll exports the whole session. The
tracker turns successive exports into a stable, append-only sequence with
cursors, recognising

* in-flight exchanges that complete between polls (updated in place, never
  counted twice),
* identical repeated requests (kept apart by occurrence number), and
* the session being cleared in Charles (reported as ``reset_detected``).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from charles5_mcp.session.model import Transaction


@dataclass
class TrackedEntry:
    entry_id: str
    txn: Transaction
    content_key: str
    position: int
    key: str = ""


@dataclass
class TrackerUpdate:
    new_ids: list[str] = field(default_factory=list)
    updated_ids: list[str] = field(default_factory=list)
    reset_detected: bool = False
    dropped: int = 0


class SessionTracker:
    def __init__(self, namespace: str, *, max_entries: int = 20_000) -> None:
        self.namespace = namespace
        self.max_entries = max(1, max_entries)
        self._order: list[str] = []  # entry ids in arrival order
        self._by_key: dict[str, TrackedEntry] = {}
        self._by_id: dict[str, TrackedEntry] = {}
        # Keys that must not be (re)admitted: the pre-capture baseline and
        # entries trimmed by max_entries that Charles still holds.
        self._ignored_keys: set[str] = set()
        self._last_export_keys: set[str] = set()
        self.offset = 0  # entries trimmed from the front (keeps cursors monotonic)
        self.resets = 0

    def _keys_for(self, transactions: list[Transaction]) -> list[tuple[str, Transaction]]:
        counts: dict[str, int] = {}
        keyed: list[tuple[str, Transaction]] = []
        for txn in transactions:
            if txn.is_control:
                continue
            identity = txn.identity_key()
            counts[identity] = counts.get(identity, 0) + 1
            keyed.append((f"{identity}#{counts[identity]}", txn))
        return keyed

    def _entry_id(self, key: str) -> str:
        digest = hashlib.sha1(f"{self.namespace}|{self.resets}|{key}".encode()).hexdigest()
        return digest[:16]

    def set_baseline(self, transactions: list[Transaction], *, include_existing: bool) -> None:
        if include_existing:
            self.ingest(transactions)
            return
        keys = {key for key, _ in self._keys_for(transactions)}
        self._ignored_keys = set(keys)
        self._last_export_keys = set(keys)

    def ingest(self, transactions: list[Transaction]) -> TrackerUpdate:
        update = TrackerUpdate()
        keyed = self._keys_for(transactions)
        current_keys = {key for key, _ in keyed}

        # A clear in Charles leaves nothing from the previous export behind.
        # Partial disappearance (Charles trimming old traffic, the user
        # deleting a row) is ordinary churn, not a reset.
        if self._last_export_keys and not (current_keys & self._last_export_keys):
            update.reset_detected = True
            self.resets += 1
        # Forget ignored keys Charles no longer holds, so the set stays bounded.
        self._ignored_keys &= current_keys

        for key, txn in keyed:
            if key in self._ignored_keys:
                continue
            existing = self._by_key.get(key)
            content = txn.content_key()
            if existing is not None:
                if existing.content_key != content:
                    existing.txn = txn
                    existing.content_key = content
                    update.updated_ids.append(existing.entry_id)
                continue
            entry_id = self._entry_id(key)
            tracked = TrackedEntry(entry_id, txn, content, self.offset + len(self._order), key)
            self._by_key[key] = tracked
            self._by_id[entry_id] = tracked
            self._order.append(entry_id)
            update.new_ids.append(entry_id)

        overflow = len(self._order) - self.max_entries
        if overflow > 0:
            for entry_id in self._order[:overflow]:
                tracked = self._by_id.pop(entry_id)
                self._by_key.pop(tracked.key, None)
                if tracked.key in current_keys:
                    self._ignored_keys.add(tracked.key)
            self._order = self._order[overflow:]
            self.offset += overflow
            update.dropped = overflow
            dropped_ids = set(update.new_ids) - set(self._order)
            update.new_ids = [i for i in update.new_ids if i not in dropped_ids]

        self._last_export_keys = current_keys
        return update

    # ----------------------------------------------------------------- access

    @property
    def total(self) -> int:
        """Absolute position after the newest entry (cursor upper bound)."""
        return self.offset + len(self._order)

    def slice(self, cursor: int, limit: int | None = None) -> list[TrackedEntry]:
        start = max(cursor - self.offset, 0)
        ids = self._order[start:] if limit is None else self._order[start : start + limit]
        return [self._by_id[i] for i in ids]

    def get(self, entry_id: str) -> TrackedEntry | None:
        return self._by_id.get(entry_id)

    def all_transactions(self) -> list[Transaction]:
        return [self._by_id[i].txn for i in self._order]
