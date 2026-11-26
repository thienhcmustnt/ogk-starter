"""
Anti-Clock-Tampering Screen-Time Tracker Skeleton (Member A — `/agent/service/time_tracker.py`).

Responsibilities (F1 & M6):
1. Measure elapsed active screen time exclusively with `time.monotonic()` (NEVER wall-clock delta!),
   so setting Windows system clock back 3 hours CANNOT extend quota.
2. Pause counting when:
   - Workstation is locked, OR
   - User idle time (Windows `GetLastInputInfo`) exceeds `policy.idle_timeout_seconds` (default 300s = 5 min).
3. Evaluate weekly schedule matrix `7 x 48` (Mon=0..Sun=6, 30-min slots) using server-synced UTC offset
   so local clock manipulation cannot bypass allowed hours.
4. Emit warnings at 10, 5, and 1 minute remaining, and provide a 60-second grace period to save homework.
5. Support remote overrides (`ADD_15M`, `LOCK_NOW`, `UNLOCK_NOW`, `PAUSE_2H`).
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from contracts.shared_schemas import PolicyConfigPayload


@dataclass
class TimeTrackerSnapshot:
    quota_used_seconds: int
    quota_limit_seconds: int
    quota_remaining_seconds: int
    is_locked: bool
    lock_reason: Optional[str]
    in_grace_period: bool
    grace_remaining_seconds: int
    warning_minute_triggered: Optional[int]


class TimeTracker:
    """Monotonic screen-time & 7x48 schedule state machine."""

    def __init__(self) -> None:
        self._policy: Optional[PolicyConfigPayload] = None
        self._last_monotonic: float = time.monotonic()
        self._active_seconds_today: float = 0.0
        self._bonus_seconds_today: int = 0
        self._server_clock_offset_sec: float = 0.0
        self._forced_locked: bool = False
        self._forced_lock_reason: Optional[str] = None
        self._grace_started_monotonic: Optional[float] = None

    def update_policy(self, policy: PolicyConfigPayload) -> None:
        self._policy = policy

    def sync_server_clock(self, server_ts: datetime) -> None:
        """Store authoritative offset vs local wall clock from `POST /api/v1/heartbeat`."""
        now_local = datetime.now(timezone.utc)
        server_utc = server_ts.astimezone(timezone.utc) if server_ts.tzinfo else server_ts.replace(tzinfo=timezone.utc)
        self._server_clock_offset_sec = (server_utc - now_local).total_seconds()

    def grant_bonus_minutes(self, minutes: int) -> None:
        self._bonus_seconds_today += max(0, minutes) * 60
        self._forced_locked = False
        self._grace_started_monotonic = None

    def force_lock(self, reason: str) -> None:
        self._forced_locked = True
        self._forced_lock_reason = reason

    def force_unlock(self) -> None:
        self._forced_locked = False
        self._forced_lock_reason = None

    def is_schedule_slot_allowed(self, local_dt: datetime) -> bool:
        """Check `schedule_matrix[weekday][half_hour_slot]` (0..6 x 0..47)."""
        if self._policy is None:
            return True
        day_idx = local_dt.weekday()
        slot_idx = local_dt.hour * 2 + (1 if local_dt.minute >= 30 else 0)
        return bool(self._policy.schedule_matrix[day_idx][slot_idx])

    def tick(self, is_user_idle: bool, is_workstation_locked: bool) -> TimeTrackerSnapshot:
        """
        TODO (Member A):
        1. Compute `delta = time.monotonic() - self._last_monotonic` (always >= 0).
        2. Advance `_active_seconds_today += delta` ONLY if not idle and not locked.
        3. Compare against weekday/weekend quota + `_bonus_seconds_today`.
        4. Trigger 10/5/1-minute warnings and 60-second grace period before lock.
        5. Also check `is_schedule_slot_allowed(...)` (outside schedule locks within 5 seconds).
        """
        raise NotImplementedError("Member A: implement TimeTracker.tick()")
