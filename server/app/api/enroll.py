"""
Device Enrollment & Token Lifecycle Endpoints (Section 4.3 & F5):
- POST   /api/v1/enroll/code: Parent generates 8-char code (valid 10 minutes)
- POST   /api/v1/enroll/device: Agent exchanges code + fingerprint for device_id,
         15m access_token, refresh_token, and per-device hmac_secret
- POST   /api/v1/enroll/refresh: Exchange refresh_token for fresh 15m access_token
- GET    /api/v1/enroll/devices/{child_id}: List devices for a child (Anti-IDOR)
- DELETE /api/v1/enroll/devices/{device_id}: Revoke device and invalidate future tokens
"""
from __future__ import annotations

import json
import secrets
from datetime import timedelta, timezone
from typing import List

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from ..core.config import settings
from ..core.database import get_db
from ..core.security import (
    create_device_access_token,
    encrypt_sensitive,
    generate_device_hmac_secret,
    generate_opaque_token,
    generate_pairing_code,
    get_authorized_child,
    get_authorized_device,
    get_client_ip,
    get_current_user,
    require_parent_csrf,
    sha256_hex,
)
from ..models.domain import AuditLog, Device, PairingCode, Policy, RevokedToken, User, utcnow
from ..schemas.payloads import (
    CreatePairingCodeRequest,
    CreatePairingCodeResponse,
    DeviceSummary,
    EnrollDeviceRequest,
    EnrollDeviceResponse,
    RefreshDeviceTokenRequest,
    RefreshDeviceTokenResponse,
)

router = APIRouter(prefix="/api/v1/enroll", tags=["enrollment"])


@router.post("/code", response_model=CreatePairingCodeResponse, status_code=status.HTTP_201_CREATED)
def create_pairing_code(
    body: CreatePairingCodeRequest,
    request: Request,
    current_user: User = Depends(require_parent_csrf),
    db: Session = Depends(get_db),
) -> CreatePairingCodeResponse:
    child = get_authorized_child(body.child_id, current_user, db, allow_child_view=False)

    # Ensure unique 8-character code
    code = generate_pairing_code(8)
    while db.query(PairingCode).filter(PairingCode.code == code).first() is not None:
        code = generate_pairing_code(8)

    expires_at = utcnow() + timedelta(minutes=settings.pairing_code_expire_minutes)
    pairing = PairingCode(
        code=code,
        child_id=child.id,
        created_by_user_id=current_user.id,
        expires_at=expires_at,
    )
    db.add(pairing)
    db.add(
        AuditLog(
            child_id=child.id,
            actor_user_id=current_user.id,
            actor_label=current_user.email,
            action="PAIRING_CODE_CREATED",
            ip_address=get_client_ip(request),
            new_value_json=json.dumps({"expires_at": expires_at.isoformat()}),
        )
    )
    db.commit()

    return CreatePairingCodeResponse(code=code, child_id=child.id, expires_at=expires_at)


@router.post("/device", response_model=EnrollDeviceResponse, status_code=status.HTTP_201_CREATED)
def enroll_device(
    body: EnrollDeviceRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> EnrollDeviceResponse:
    code_norm = body.code.strip().upper()
    pairing = db.query(PairingCode).filter(PairingCode.code == code_norm).first()
    if pairing is None or pairing.used_at is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or already-used pairing code",
        )

    now = utcnow()
    exp = (
        pairing.expires_at.replace(tzinfo=timezone.utc)
        if pairing.expires_at.tzinfo is None
        else pairing.expires_at
    )
    if exp < now:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Pairing code has expired",
        )

    device_id = f"dev_{secrets.token_hex(8)}"
    raw_refresh_token = generate_opaque_token()
    raw_hmac_secret = generate_device_hmac_secret()

    device = Device(
        id=device_id,
        child_id=pairing.child_id,
        device_name=body.device_name.strip(),
        fingerprint_hash=sha256_hex(body.device_fingerprint),
        os_version=body.os_version.strip(),
        hmac_secret_enc=encrypt_sensitive(raw_hmac_secret),
        refresh_token_hash=sha256_hex(raw_refresh_token),
        last_policy_version=0,
    )
    pairing.used_at = now
    db.add(device)
    db.add(
        AuditLog(
            child_id=pairing.child_id,
            actor_user_id=pairing.created_by_user_id,
            actor_label=f"device:{device_id}",
            action="DEVICE_ENROLLED",
            ip_address=get_client_ip(request),
            new_value_json=json.dumps(
                {"device_id": device_id, "device_name": device.device_name, "os_version": device.os_version},
                ensure_ascii=False,
            ),
        )
    )
    db.commit()
    db.refresh(device)

    access_token, _ = create_device_access_token(device)
    policy = db.query(Policy).filter(Policy.child_id == device.child_id).first()
    policy_version = policy.version if policy else 0

    return EnrollDeviceResponse(
        device_id=device.id,
        child_id=device.child_id,
        access_token=access_token,
        refresh_token=raw_refresh_token,
        hmac_secret=raw_hmac_secret,
        policy_version=policy_version,
    )


@router.post("/refresh", response_model=RefreshDeviceTokenResponse)
def refresh_device_token(
    body: RefreshDeviceTokenRequest,
    db: Session = Depends(get_db),
) -> RefreshDeviceTokenResponse:
    device = db.query(Device).filter(Device.id == body.device_id).first()
    if device is None or device.revoked_at is not None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Device not found or has been revoked",
        )

    if sha256_hex(body.refresh_token) != device.refresh_token_hash:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        )

    access_token, _ = create_device_access_token(device)
    return RefreshDeviceTokenResponse(
        device_id=device.id,
        access_token=access_token,
        expires_in_seconds=settings.access_token_expire_minutes * 60,
    )


@router.get("/devices/{child_id}", response_model=List[DeviceSummary])
def list_child_devices(
    child_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> List[DeviceSummary]:
    get_authorized_child(child_id, current_user, db, allow_child_view=True)
    devices = db.query(Device).filter(Device.child_id == child_id).order_by(Device.enrolled_at.desc()).all()
    return [
        DeviceSummary(
            id=d.id,
            child_id=d.child_id,
            device_name=d.device_name,
            os_version=d.os_version,
            last_heartbeat_at=d.last_heartbeat_at,
            last_policy_version=d.last_policy_version,
            last_quota_used_sec=d.last_quota_used_sec,
            tray_visible=d.tray_visible,
            revoked_at=d.revoked_at,
        )
        for d in devices
    ]


@router.delete("/devices/{device_id}")
def revoke_device(
    device_id: str,
    request: Request,
    current_user: User = Depends(require_parent_csrf),
    db: Session = Depends(get_db),
) -> dict:
    device = get_authorized_device(device_id, current_user, db, allow_child_view=False)
    if device.revoked_at is not None:
        return {"device_id": device.id, "status": "already_revoked"}

    now = utcnow()
    device.revoked_at = now
    # Also record a sentinel revocation entry for auditability
    db.add(
        RevokedToken(
            jti=f"device_revoked_{device.id}_{secrets.token_hex(4)}",
            device_id=device.id,
            reason="parent_revoked_device",
            revoked_at=now,
        )
    )
    db.add(
        AuditLog(
            child_id=device.child_id,
            actor_user_id=current_user.id,
            actor_label=current_user.email,
            action="DEVICE_REVOKED",
            ip_address=get_client_ip(request),
            old_value_json=json.dumps({"device_id": device.id, "device_name": device.device_name}),
            new_value_json=json.dumps({"revoked_at": now.isoformat()}),
        )
    )
    db.commit()
    return {"device_id": device.id, "status": "revoked"}
