"""
60-Second Device Heartbeat & Anti-Clock-Tampering Detection (M6):
- Compares server UTC timestamp vs `device_ts`.
- If abs(server_ts - device_ts) > 120s: writes CLOCK_SKEW_DETECTED to `audit_logs`
  and returns `clock_skew_detected: true` with authoritative `server_ts`.
- Returns latest `policy_version` and any undelivered `pending_commands`.
"""
from __future__ import annotations

import json
from datetime import timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from ..core.config import settings
from ..core.database import get_db
from ..core.security import get_client_ip, get_current_device
from ..models.domain import AuditLog, Device, PendingCommand, Policy, utcnow
from ..schemas.payloads import HeartbeatRequest, HeartbeatResponse, PendingCommandOut

router = APIRouter(prefix="/api/v1", tags=["heartbeat"])


@router.post("/heartbeat", response_model=HeartbeatResponse)
def device_heartbeat(
    body: HeartbeatRequest,
    request: Request,
    device: Device = Depends(get_current_device),
    db: Session = Depends(get_db),
) -> HeartbeatResponse:
    if body.device_id != device.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Token device_id mismatch",
        )

    server_ts = utcnow()
    device_ts = (
        body.device_ts.replace(tzinfo=timezone.utc)
        if body.device_ts.tzinfo is None
        else body.device_ts.astimezone(timezone.utc)
    )
    skew_seconds = int(abs((server_ts - device_ts).total_seconds()))
    clock_skew_detected = skew_seconds > settings.clock_skew_threshold_seconds

    device.last_heartbeat_at = server_ts
    device.last_policy_version = body.policy_version
    device.last_quota_used_sec = body.quota_used_seconds
    device.tray_visible = body.tray_visible

    if clock_skew_detected:
        db.add(
            AuditLog(
                child_id=device.child_id,
                actor_user_id=None,
                actor_label=f"device:{device.id}",
                action="CLOCK_SKEW_DETECTED",
                ip_address=get_client_ip(request),
                old_value_json=json.dumps({"device_ts": device_ts.isoformat()}),
                new_value_json=json.dumps(
                    {
                        "server_ts": server_ts.isoformat(),
                        "skew_seconds": skew_seconds,
                        "threshold_seconds": settings.clock_skew_threshold_seconds,
                    }
                ),
            )
        )

    # Anti-stalkerware NT1 audit if tray icon unexpectedly became invisible
    if not body.tray_visible:
        db.add(
            AuditLog(
                child_id=device.child_id,
                actor_user_id=None,
                actor_label=f"device:{device.id}",
                action="NT1_TRAY_NOT_VISIBLE_ALERT",
                ip_address=get_client_ip(request),
                new_value_json=json.dumps(
                    {"device_id": device.id, "agent_status": body.agent_status}
                ),
            )
        )

    policy = db.query(Policy).filter(Policy.child_id == device.child_id).first()
    latest_version = policy.version if policy else 0

    pending_rows = (
        db.query(PendingCommand)
        .filter(
            PendingCommand.device_id == device.id,
            PendingCommand.acked_at.is_(None),
        )
        .order_by(PendingCommand.id.asc())
        .all()
    )
    commands_out = []
    for row in pending_rows:
        commands_out.append(
            PendingCommandOut(
                command_id=row.id,
                command=row.command,
                payload=json.loads(row.payload_json or "{}"),
                issued_by=row.issued_by,
                created_at=row.created_at,
            )
        )
        if row.delivered_at is None:
            row.delivered_at = server_ts

    db.commit()

    return HeartbeatResponse(
        server_ts=server_ts,
        clock_skew_detected=clock_skew_detected,
        skew_seconds=skew_seconds,
        latest_policy_version=latest_version,
        policy_update_required=body.policy_version < latest_version,
        pending_commands=commands_out,
    )
