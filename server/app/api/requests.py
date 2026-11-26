"""
NT3 Child Voice Endpoints:
- POST /api/v1/requests: Submit `unlock_request` or `false_positive_report`
      (via Device Bearer token or `child-view` web session + CSRF)
- GET  /api/v1/requests/{child_id}: View requests & parent responses (parent & child-view)
- POST /api/v1/requests/{request_id}/decision: Parent approves or rejects with explanation;
      approved unlock requests immediately dispatch `ADD_15M` to child's devices.
"""
from __future__ import annotations

import json
import secrets
from typing import List, Optional, Tuple

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from sqlalchemy.orm import Session

from ..core.database import get_db
from ..core.security import (
    get_authorized_child,
    get_client_ip,
    get_current_user,
    get_optional_user_or_device,
    require_parent_csrf,
)
from ..models.domain import AuditLog, ChildRequest, Device, Event, User, UserSession, utcnow
from ..schemas.payloads import (
    ChildRequestOut,
    CreateChildRequestPayload,
    DecisionChildRequestPayload,
)
from .ws import dispatch_device_command

router = APIRouter(prefix="/api/v1/requests", tags=["child requests (NT3)"])


def _to_out(row: ChildRequest) -> ChildRequestOut:
    return ChildRequestOut(
        id=row.id,
        child_id=row.child_id,
        device_id=row.device_id,
        request_type=row.request_type,
        subject=row.subject,
        message=row.message,
        requested_minutes=row.requested_minutes,
        status=row.status,
        parent_response=row.parent_response,
        created_at=row.created_at,
        reviewed_at=row.reviewed_at,
    )


@router.post("", response_model=ChildRequestOut, status_code=status.HTTP_201_CREATED)
def submit_child_request(
    body: CreateChildRequestPayload,
    request: Request,
    x_csrf_token: Optional[str] = Header(default=None, alias="X-CSRF-Token"),
    actor: Tuple[Optional[User], Optional[Device]] = Depends(get_optional_user_or_device),
    db: Session = Depends(get_db),
) -> ChildRequestOut:
    user, device = actor
    target_child_id: int
    source_device_id: Optional[str] = None

    if device is not None:
        target_child_id = device.child_id
        source_device_id = device.id
    elif user is not None:
        # Enforce CSRF for cookie-based web sessions
        active_session = (
            db.query(UserSession)
            .filter(
                UserSession.user_id == user.id,
                UserSession.revoked_at.is_(None),
                UserSession.csrf_token == (x_csrf_token or ""),
            )
            .first()
        )
        if active_session is None:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid or missing CSRF token",
            )
        if user.role == "child-view":
            if user.linked_child_id is None:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No child profile linked")
            target_child_id = user.linked_child_id
        else:
            if body.child_id is None:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="child_id is required")
            child = get_authorized_child(body.child_id, user, db, allow_child_view=True)
            target_child_id = child.id
    else:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")

    req_row = ChildRequest(
        child_id=target_child_id,
        device_id=source_device_id,
        request_type=body.request_type.value,
        subject=body.subject,
        message=body.message.strip(),
        requested_minutes=body.requested_minutes if body.request_type.value == "unlock_request" else None,
        status="pending",
    )
    db.add(req_row)

    # Record NT3 unlock_request event if submitted from a device
    if source_device_id is not None and body.request_type.value == "unlock_request":
        db.add(
            Event(
                idempotency_key=f"unlock_req_{source_device_id}_{secrets.token_hex(8)}",
                ts=utcnow(),
                device_id=source_device_id,
                child_id=target_child_id,
                type="unlock_request",
                subject=body.subject,
                duration_sec=0,
            )
        )

    db.commit()
    db.refresh(req_row)
    return _to_out(req_row)


@router.get("/{child_id}", response_model=List[ChildRequestOut])
def list_child_requests(
    child_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> List[ChildRequestOut]:
    child = get_authorized_child(child_id, current_user, db, allow_child_view=True)
    rows = (
        db.query(ChildRequest)
        .filter(ChildRequest.child_id == child.id)
        .order_by(ChildRequest.created_at.desc(), ChildRequest.id.desc())
        .all()
    )
    return [_to_out(r) for r in rows]


@router.post("/{request_id}/decision", response_model=ChildRequestOut)
async def decide_child_request(
    request_id: int,
    body: DecisionChildRequestPayload,
    request: Request,
    current_user: User = Depends(require_parent_csrf),
    db: Session = Depends(get_db),
) -> ChildRequestOut:
    req_row = db.query(ChildRequest).filter(ChildRequest.id == request_id).first()
    if req_row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Child request not found")

    # Anti-IDOR ownership check
    get_authorized_child(req_row.child_id, current_user, db, allow_child_view=False)

    old_status = req_row.status
    req_row.status = body.decision.value
    req_row.parent_response = body.response_message.strip()
    req_row.reviewed_by_user_id = current_user.id
    req_row.reviewed_at = utcnow()

    db.add(
        AuditLog(
            child_id=req_row.child_id,
            actor_user_id=current_user.id,
            actor_label=current_user.email,
            action=f"CHILD_REQUEST_{body.decision.value.upper()}",
            ip_address=get_client_ip(request),
            old_value_json=json.dumps({"request_id": req_row.id, "status": old_status}),
            new_value_json=json.dumps(
                {
                    "request_id": req_row.id,
                    "request_type": req_row.request_type,
                    "subject": req_row.subject,
                    "status": req_row.status,
                    "parent_response": req_row.parent_response,
                },
                ensure_ascii=False,
            ),
        )
    )
    db.commit()
    db.refresh(req_row)

    # If parent approved an unlock_request, push ADD_15M / granted minutes to child's active devices
    if body.decision.value == "approved" and req_row.request_type == "unlock_request":
        grant_minutes = body.grant_minutes or req_row.requested_minutes or 15
        devices = (
            db.query(Device)
            .filter(Device.child_id == req_row.child_id, Device.revoked_at.is_(None))
            .all()
        )
        for dev in devices:
            await dispatch_device_command(
                db=db,
                device_id=dev.id,
                child_id=req_row.child_id,
                command_name="ADD_15M",
                payload={"minutes": grant_minutes, "reason": req_row.parent_response},
                issued_by=current_user.email,
                actor_user_id=current_user.id,
                ip_address=get_client_ip(request),
            )
            db.add(
                Event(
                    idempotency_key=f"override_{req_row.id}_{dev.id}_{secrets.token_hex(4)}",
                    ts=utcnow(),
                    device_id=dev.id,
                    child_id=req_row.child_id,
                    type="override_granted",
                    subject=req_row.subject,
                    duration_sec=grant_minutes * 60,
                )
            )
        db.commit()

    return _to_out(req_row)
