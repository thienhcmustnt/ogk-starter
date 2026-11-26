"""
OGK Windows Service Skeleton (Member A — `/agent/service/windows_service.py`).

Responsibilities:
1. Run under `LocalSystem` via `pywin32` (`win32serviceutil.ServiceFramework`).
2. Configure SCM Recovery Options (`sc failure OGKAgentService reset= 86400 actions= restart/5000/restart/5000/restart/10000`).
3. Orchestrate sub-components:
   - `LocalStore`: Load HMAC-verified cached policy from `C:\\ProgramData\\OGK\\agent_cache.db`
   - `DNSProxyServer`: Start UDP/TCP DNS proxy at `127.0.0.1:53`
   - `AppController`: Scan running processes + SHA-256 executable hashes
   - `TimeTracker`: Track screen time via `time.monotonic()` & 7x48 schedule matrix
   - `LocalIPCServer`: Serve `127.0.0.1:47891` for Tray UI (Member B)
   - Server Sync Worker: 60s `POST /api/v1/heartbeat`, WS `/ws/device/{id}`, batch `POST /api/v1/events/batch`
4. Anti-Stalkerware Rule (NT1):
   - NEVER hide this service or process.
   - Monitor Tray UI heartbeat via `LocalIPCServer`; if Tray UI cannot display its icon
     in the active user session, pause stealth enforcement and report `tray_visible=false`.
"""
from __future__ import annotations

import logging
import threading
from typing import Optional

logger = logging.getLogger("ogk.agent.service")

try:
    import servicemanager  # type: ignore
    import win32event  # type: ignore
    import win32service  # type: ignore
    import win32serviceutil  # type: ignore

    HAS_PYWIN32 = True
except ImportError:
    HAS_PYWIN32 = False


class OGKServiceCore:
    """Platform-independent orchestrator so Member A can test locally before installing as SCM Service."""

    def __init__(self, server_base_url: str, cert_pin_sha256: Optional[str] = None) -> None:
        self.server_base_url = server_base_url.rstrip("/")
        self.cert_pin_sha256 = cert_pin_sha256
        self._stop_event = threading.Event()

    def start(self) -> None:
        """
        TODO (Member A):
        1. Load enrolled device credentials & cached policy via `LocalStore`.
        2. Verify cached policy signature with `contracts.shared_schemas.verify_policy_signature`.
        3. Start `DNSProxyServer`, `AppController`, `TimeTracker`, `LocalIPCServer`.
        4. Start 60s heartbeat loop + WebSocket listener (with TLS certificate pinning).
        5. Verify Tray UI visibility (NT1); stop enforcement if Tray UI cannot be displayed.
        """
        logger.info("OGKServiceCore starting (server=%s)", self.server_base_url)
        raise NotImplementedError("Member A: implement OGKServiceCore.start()")

    def stop(self) -> None:
        """Gracefully shut down DNS proxy, flush offline event queue, and restore DNS if needed."""
        logger.info("OGKServiceCore stopping...")
        self._stop_event.set()


if HAS_PYWIN32:

    class OGKWindowsService(win32serviceutil.ServiceFramework):
        _svc_name_ = "OGKAgentService"
        _svc_display_name_ = "OGK Companion Safety Service"
        _svc_description_ = (
            "OGK transparent parental companion service (NT1-NT6). "
            "Not stealth software; always paired with OGK Tray UI."
        )

        def __init__(self, args) -> None:
            win32serviceutil.ServiceFramework.__init__(self, args)
            self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
            self.core = OGKServiceCore(server_base_url="https://127.0.0.1:8000")

        def SvcStop(self) -> None:
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            self.core.stop()
            win32event.SetEvent(self.hWaitStop)

        def SvcDoRun(self) -> None:
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, ""),
            )
            self.core.start()


if __name__ == "__main__":
    if HAS_PYWIN32:
        win32serviceutil.HandleCommandLine(OGKWindowsService)
    else:
        print("pywin32 not installed. Run on Windows with `pip install -r agent/requirements.txt`.")
