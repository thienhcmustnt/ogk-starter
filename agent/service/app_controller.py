"""
Process & Executable SHA-256 App Controller Skeleton (Member A — `/agent/service/app_controller.py`).

Responsibilities (F2 + NT4 + NT6):
1. Poll running user processes using `psutil.process_iter(['pid', 'name', 'exe'])`.
2. Compute and cache SHA-256 hash of each executable path so renaming `notepad.exe` -> `game.exe`
   (or vice-versa) is STILL accurately detected!
3. NEVER terminate NT6 immutable system/transparency apps (`NT6_IMMUTABLE_WHITELIST_APPS`).
4. When a blocked app is detected:
   - Terminate the process cleanly (`proc.terminate()`, fallback `proc.kill()`).
   - Emit `LocalIPCBlockNotice` with `reason` and `created_by` to Tray UI (NT4 — NEVER silent!).
   - Enqueue NT2-compliant `blocked_app` event (only executable filename, NEVER full path or window title).
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Callable, Dict, Optional

from contracts.shared_schemas import (
    LocalIPCBlockNotice,
    NT6_IMMUTABLE_WHITELIST_APPS,
    PolicyConfigPayload,
)


def compute_file_sha256(file_path: str | Path) -> Optional[str]:
    """Compute hex SHA-256 of an executable file in 64 KiB chunks."""
    try:
        hasher = hashlib.sha256()
        with open(file_path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                hasher.update(chunk)
        return hasher.hexdigest().lower()
    except (OSError, PermissionError):
        return None


class AppController:
    """Monitors running applications and enforces allow/block rules by name + SHA-256."""

    def __init__(
        self,
        poll_interval_seconds: float = 2.0,
        on_block_callback: Optional[Callable[[LocalIPCBlockNotice], None]] = None,
    ) -> None:
        self.poll_interval_seconds = poll_interval_seconds
        self.on_block_callback = on_block_callback
        self._policy: Optional[PolicyConfigPayload] = None
        self._sha256_cache: Dict[str, str] = {}

    def update_policy(self, policy: PolicyConfigPayload) -> None:
        self._policy = policy

    def is_protected_app(self, exe_name: str) -> bool:
        return exe_name.strip().lower() in NT6_IMMUTABLE_WHITELIST_APPS

    def scan_once(self) -> int:
        """
        TODO (Member A):
        1. Iterate processes with `psutil.process_iter(['pid', 'name', 'exe'])`.
        2. Skip protected NT6 processes.
        3. Match against `policy.blocked_apps` by BOTH `target` (exe name) AND `sha256`.
        4. Terminate matching process, notify Tray UI (NT4), and log NT2 `blocked_app` event.
        Returns number of processes terminated in this sweep.
        """
        raise NotImplementedError("Member A: implement AppController.scan_once()")
