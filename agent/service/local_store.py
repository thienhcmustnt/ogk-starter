"""
Local Offline SQLite Cache & Event Queue Skeleton (Member A — `/agent/service/local_store.py`).

Location on Windows:
    `C:\\ProgramData\\OGK\\agent_cache.db`
    ACL MUST be restricted so ONLY `SYSTEM` and `Administrators` have Write permission
    (child's standard Windows user account gets denied Write access).

Responsibilities:
1. Persist enrolled credentials (`device_id`, `child_id`, `refresh_token`, `hmac_secret`).
2. Cache the latest `SignedPolicyEnvelope` and ALWAYS re-verify its HMAC-SHA256 signature
   via `contracts.shared_schemas.verify_policy_signature()` upon loading!
3. Queue `TelemetryEventItem` events offline with unique `idempotency_key`s and flush them
   in batches to `POST /api/v1/events/batch` when connectivity returns.
4. Implement `purge_local_cache()` invoked immediately upon receiving `PURGE_CACHE` command (F3).
"""
from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import List, Optional

from contracts.shared_schemas import (
    PolicyConfigPayload,
    SignedPolicyEnvelope,
    TelemetryEventItem,
    verify_policy_signature,
)


DEFAULT_CACHE_PATH = Path(r"C:\ProgramData\OGK\agent_cache.db")


class LocalStore:
    """SQLite cache and offline sync queue for OGK Windows Service."""

    def __init__(self, db_path: Path = DEFAULT_CACHE_PATH) -> None:
        self.db_path = db_path
        self._conn: Optional[sqlite3.Connection] = None

    def initialize(self) -> None:
        """
        TODO (Member A):
        Create parent directory, enable WAL mode, create tables:
        - `kv_state(key PRIMARY KEY, value)`
        - `cached_policy(id PRIMARY KEY, envelope_json, saved_at)`
        - `event_queue(idempotency_key PRIMARY KEY, payload_json, created_at)`
        """
        raise NotImplementedError("Member A: implement LocalStore.initialize()")

    def save_signed_policy(self, envelope: SignedPolicyEnvelope, hmac_secret: str) -> None:
        """Verify HMAC signature BEFORE saving to disk."""
        if not verify_policy_signature(envelope.policy, envelope.signature, hmac_secret):
            raise ValueError("Refusing to cache policy with invalid HMAC-SHA256 signature!")
        raise NotImplementedError("Member A: persist verified policy envelope")

    def load_verified_policy(self, hmac_secret: str) -> Optional[PolicyConfigPayload]:
        """Load cached policy and reject if tampered on disk."""
        raise NotImplementedError("Member A: load and verify cached policy")

    def enqueue_event(self, event: TelemetryEventItem) -> None:
        raise NotImplementedError("Member A: insert event into offline queue")

    def pop_event_batch(self, limit: int = 100) -> List[TelemetryEventItem]:
        raise NotImplementedError("Member A: read oldest unsent events")

    def mark_events_synced(self, idempotency_keys: List[str]) -> None:
        raise NotImplementedError("Member A: delete synced keys from queue")

    def purge_local_cache(self) -> None:
        """F3: Wipe all queued/historical telemetry events on `PURGE_CACHE` command."""
        raise NotImplementedError("Member A: wipe local event history")
