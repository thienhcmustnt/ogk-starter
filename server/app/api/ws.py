"""
Real-time Command Channel (< 5s latency):
- WebSocket endpoint: /ws/device/{device_id}?token=<device_access_token>
- REST endpoint: POST /api/v1/commands/{device_id}
Supports: LOCK_NOW, UNLOCK_NOW, ADD_15M, PURGE_CACHE, PAUSE_2H, SYNC_POLICY.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, WebSocket, WebSocketDisconnect, status
from sqlalchemy.orm import Session

from ..core.database import get_db
from ..core.security import (
    decode_device_access_token,
    get_authorized_device,
    get_client_ip,
    require_parent_csrf,
)
from ..models.domain import AuditLog, PendingCommand, User, utcnow
from ..schemas.payloads import SendCommandRequest, SendCommandResponse

logger = logging.getLogger("ogk.ws")
router = APIRouter(tags=["commands & websocket"])


class DeviceConnectionManager:
    """Tracks active WebSocket connections keyed by device_id."""

    def __init__(self) -> None:
        self._connections: Dict[str, WebSocket] = {}

    async def connect(self, device_id: str, websocket: WebSocket) -> None:
        await websocket.accept()
        self._connections[device_id] = websocket

    def disconnect(self, device_id: str, websocket: WebSocket) -> None:
        if self._connections.get(device_id) is websocket:
            del self._connections[device_id]

    def is_connected(self, device_id: str) -> bool:
        return device_id in self._connections

    async def push_command(self, device_id: str, message: Dict[str, Any]) -> bool:
        ws = self._connections.get(device_id)
        if ws is None:
            return False
        try:
            await ws.send_json(message)
            return True
        except Exception:
            logger.warning("Failed to push WS command to %s; falling back to queue", device_id)
            self._connections.pop(device_id, None)
            return False


ws_manager = DeviceConnectionManager()


async def dispatch_device_command(
    db: Session,
    device_id: str,
    child_id: int,
    command_name: str,
    payload: Dict[str, Any],
    issued_by: str,
    actor_user_id: Optional[int],
    ip_address: str,
) -> tuple[PendingCommand, bool]:
    """Persist command and immediately push over WebSocket if device is online."""
    cmd = PendingCommand(
        device_id=device_id,
        command=command_name,
        payload_json=json.dumps(payload, ensure_ascii=False),
        issued_by=issued_by,
    )
    db.add(cmd)
    db.add(
        AuditLog(
            child_id=child_id,
            actor_user_id=actor_user_id,
            actor_label=issued_by,
            action=f"COMMAND_{command_name}",
            ip_address=ip_address,
            new_value_json=json.dumps(
                {"device_id": device_id, "command": command_name, "payload": payload},
                ensure_ascii=False,
            ),
        )
    )
    db.commit()
    db.refresh(cmd)

    ws_payload = {
        "type": "COMMAND",
        "command_id": cmd.id,
        "command": cmd.command,
        "payload": payload,
        "issued_by": issued_by,
        "issued_at": cmd.created_at.isoformat(),
    }
    delivered = await ws_manager.push_command(device_id, ws_payload)
    if delivered:
        cmd.delivered_at = utcnow()
        db.commit()

    return cmd, delivered


@router.websocket("/ws/device/{device_id}")
async def device_websocket_endpoint(
    websocket: WebSocket,
    device_id: str,
    token: str = Query(..., description="Device JWT access token"),
    db: Session = Depends(get_db),
) -> None:
    try:
        device = decode_device_access_token(token, db)
    except HTTPException:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    if device.id != device_id:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await ws_manager.connect(device_id, websocket)
    try:
        # Flush any undelivered commands upon reconnect
        undelivered = (
            db.query(PendingCommand)
            .filter(
                PendingCommand.device_id == device_id,
                PendingCommand.acked_at.is_(None),
            )
            .order_by(PendingCommand.id.asc())
            .all()
        )
        for cmd in undelivered:
            await websocket.send_json(
                {
                    "type": "COMMAND",
                    "command_id": cmd.id,
                    "command": cmd.command,
                    "payload": json.loads(cmd.payload_json or "{}"),
                    "issued_by": cmd.issued_by,
                    "issued_at": cmd.created_at.isoformat(),
                }
            )
            cmd.delivered_at = utcnow()
        if undelivered:
            db.commit()

        while True:
            raw = await websocket.receive_json()
            msg_type = raw.get("type")
            if msg_type == "ACK" and "command_id" in raw:
                cmd = (
                    db.query(PendingCommand)
                    .filter(
                        PendingCommand.id == int(raw["command_id"]),
                        PendingCommand.device_id == device_id,
                    )
                    .first()
                )
                if cmd is not None:
                    cmd.acked_at = utcnow()
                    db.commit()
            elif msg_type == "PING":
                await websocket.send_json({"type": "PONG", "server_ts": utcnow().isoformat()})
    except WebSocketDisconnect:
        ws_manager.disconnect(device_id, websocket)
    except Exception:
        ws_manager.disconnect(device_id, websocket)


@router.post("/api/v1/commands/{device_id}", response_model=SendCommandResponse)
async def send_remote_command(
    device_id: str,
    body: SendCommandRequest,
    request: Request,
    current_user: User = Depends(require_parent_csrf),
    db: Session = Depends(get_db),
) -> SendCommandResponse:
    device = get_authorized_device(device_id, current_user, db, allow_child_view=False)
    if device.revoked_at is not None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Device has been revoked")

    cmd, delivered = await dispatch_device_command(
        db=db,
        device_id=device.id,
        child_id=device.child_id,
        command_name=body.command.value,
        payload=body.payload,
        issued_by=current_user.email,
        actor_user_id=current_user.id,
        ip_address=get_client_ip(request),
    )
    return SendCommandResponse(
        command_id=cmd.id,
        device_id=device.id,
        command=cmd.command,
        delivered_via_ws=delivered,
    )
