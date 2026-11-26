"""
Local IPC Server Skeleton (Member A <-> Member B Bridge — `/agent/service/ipc_server.py`).

Implements the local-only HTTP JSON protocol documented in `contracts/api_contract.md` Section 9:
- Binds strictly to `127.0.0.1:47891`.
- Authenticated by a random local token written to `C:\\ProgramData\\OGK\\ipc_token.txt`
  (ACL: SYSTEM/Admin Write, Users Read) sent in header `X-OGK-IPC-Token`.
- Endpoints:
  - `GET  /ipc/status`        -> returns `LocalIPCStatusResponse`
  - `GET  /ipc/notifications` -> returns pending `LocalIPCBlockNotice` list
  - `POST /ipc/tray-heartbeat`-> Tray UI confirms visible icon every 10s (NT1)
  - `POST /ipc/request`       -> Forward child's NT3 request to Server
  - `GET  /ipc/today-summary` -> Today's usage for child's transparency window
"""
from __future__ import annotations

import secrets
import time
from pathlib import Path
from typing import List

from contracts.shared_schemas import LocalIPCBlockNotice, LocalIPCStatusResponse

IPC_HOST = "127.0.0.1"
IPC_PORT = 47891
IPC_TOKEN_PATH = Path(r"C:\ProgramData\OGK\ipc_token.txt")


class LocalIPCServer:
    """Bridge server running inside Windows Service for Tray UI communication."""

    def __init__(self, host: str = IPC_HOST, port: int = IPC_PORT) -> None:
        self.host = host
        self.port = port
        self.ipc_token = secrets.token_hex(24)
        self._last_tray_heartbeat_monotonic: float = 0.0
        self._pending_notices: List[LocalIPCBlockNotice] = []

    def push_block_notice(self, notice: LocalIPCBlockNotice) -> None:
        self._pending_notices.append(notice)

    def record_tray_heartbeat(self) -> None:
        self._last_tray_heartbeat_monotonic = time.monotonic()

    def is_tray_alive(self, timeout_seconds: float = 30.0) -> bool:
        """NT1 anti-stalkerware guard: True only if Tray UI checked in recently."""
        if self._last_tray_heartbeat_monotonic == 0.0:
            return False
        return (time.monotonic() - self._last_tray_heartbeat_monotonic) <= timeout_seconds

    def get_status(self) -> LocalIPCStatusResponse:
        raise NotImplementedError("Member A: wire LocalIPCServer.get_status() to TimeTracker & LocalStore")

    def start(self) -> None:
        """TODO (Member A): Write `ipc_token` to ProgramData and start lightweight ThreadingHTTPServer."""
        raise NotImplementedError("Member A: implement LocalIPCServer.start()")
