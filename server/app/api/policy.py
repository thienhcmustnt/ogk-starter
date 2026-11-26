"""
Policy Management Endpoints (NT4, NT6, HMAC-SHA256 Integrity):
- GET /api/v1/policy/{child_id}: Retrieve canonical signed policy envelope
- PUT /api/v1/policy/{child_id}: Update policy, bump version, re-sign HMAC-SHA256,
      enforce NT4/NT6, record AuditLog, and push SYNC_POLICY via WS
- GET /api/v1/policy/domains/catalog: Read safe 220+ categorized domain database
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import ValidationError
from sqlalchemy.orm import Session

_PROJECT_ROOT = str(Path(__file__).resolve().parents[3])
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from contracts.shared_schemas import PolicyConfigPayload, SignedPolicyEnvelope, sign_policy_payload  # noqa: E402

from ..core.config import settings  # noqa: E402
from ..core.database import get_db  # noqa: E402
from ..core.security import (  # noqa: E402
    decrypt_sensitive,
    get_authorized_child,
    get_client_ip,
    get_optional_user_or_device,
    require_parent_csrf,
)
from ..models.domain import AuditLog, Device, DomainCategory, Policy, User, utcnow  # noqa: E402
from ..schemas.payloads import PolicyUpdateRequest  # noqa: E402
from .ws import dispatch_device_command  # noqa: E402

router = APIRouter(prefix="/api/v1/policy", tags=["policy"])


@router.get("/domains/catalog")
def get_domain_catalog(
    category: Optional[str] = None,
    db: Session = Depends(get_db),
) -> Dict[str, object]:
    query = db.query(DomainCategory)
    if category:
        query = query.filter(DomainCategory.category == category)
    rows = query.order_by(DomainCategory.category.asc(), DomainCategory.domain.asc()).all()
    return {
        "total": len(rows),
        "domains": [
            {
                "domain": r.domain,
                "category": r.category,
                "is_doh_endpoint": r.is_doh_endpoint,
                "is_doh_canary": r.is_doh_canary,
                "is_emergency_whitelist": r.is_emergency_whitelist,
            }
            for r in rows
        ],
    }


@router.get("/{child_id}", response_model=SignedPolicyEnvelope)
def get_policy(
    child_id: int,
    actor: Tuple[Optional[User], Optional[Device]] = Depends(get_optional_user_or_device),
    db: Session = Depends(get_db),
) -> SignedPolicyEnvelope:
    user, device = actor

    if device is not None:
        if device.child_id != child_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Device is not authorized for this child's policy",
            )
    elif user is not None:
        get_authorized_child(child_id, user, db, allow_child_view=True)

    policy_row = db.query(Policy).filter(Policy.child_id == child_id).first()
    if policy_row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Policy not found")

    policy_obj = PolicyConfigPayload.model_validate(json.loads(policy_row.config_json))

    # Sign with per-device HMAC secret when fetched by an enrolled device,
    # or master policy key for dashboard/user verification.
    if device is not None:
        device_secret = decrypt_sensitive(device.hmac_secret_enc)
        signature = sign_policy_payload(policy_obj, device_secret)
    else:
        signature = policy_row.signature

    return SignedPolicyEnvelope(
        policy=policy_obj,
        updated_at=policy_row.updated_at,
        signature_alg="HMAC-SHA256",
        signature=signature,
    )


@router.put("/{child_id}", response_model=SignedPolicyEnvelope)
async def update_policy(
    child_id: int,
    body: PolicyUpdateRequest,
    request: Request,
    current_user: User = Depends(require_parent_csrf),
    db: Session = Depends(get_db),
) -> SignedPolicyEnvelope:
    child = get_authorized_child(child_id, current_user, db, allow_child_view=False)
    policy_row = db.query(Policy).filter(Policy.child_id == child.id).first()

    old_snapshot = None
    next_version = 1
    if policy_row is not None:
        old_snapshot = json.loads(policy_row.config_json)
        next_version = policy_row.version + 1

    raw_payload = body.model_dump(exclude={"change_note"})
    raw_payload["child_id"] = child.id
    raw_payload["version"] = next_version

    try:
        validated_policy = PolicyConfigPayload.model_validate(raw_payload)
    except ValidationError as exc:
        raise HTTPException(
            status_code=422,
            detail=json.loads(exc.json()),
        )

    canonical_json = json.dumps(
        validated_policy.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    signature = sign_policy_payload(validated_policy, settings.policy_hmac_master_key)
    now = utcnow()

    if policy_row is None:
        policy_row = Policy(
            child_id=child.id,
            version=next_version,
            config_json=canonical_json,
            signature=signature,
            updated_by_user_id=current_user.id,
            updated_at=now,
        )
        db.add(policy_row)
    else:
        policy_row.version = next_version
        policy_row.config_json = canonical_json
        policy_row.signature = signature
        policy_row.updated_by_user_id = current_user.id
        policy_row.updated_at = now

    db.add(
        AuditLog(
            child_id=child.id,
            actor_user_id=current_user.id,
            actor_label=current_user.email,
            action="POLICY_UPDATED",
            ip_address=get_client_ip(request),
            old_value_json=json.dumps(old_snapshot, ensure_ascii=False) if old_snapshot else None,
            new_value_json=json.dumps(
                {
                    "version": next_version,
                    "change_note": body.change_note,
                    "weekday_quota_minutes": validated_policy.weekday_quota_minutes,
                    "weekend_quota_minutes": validated_policy.weekend_quota_minutes,
                    "blocked_domains_count": len(validated_policy.blocked_domains),
                    "blocked_apps_count": len(validated_policy.blocked_apps),
                },
                ensure_ascii=False,
            ),
        )
    )
    db.commit()
    db.refresh(policy_row)

    # Notify active devices to sync the new policy version immediately
    active_devices: List[Device] = (
        db.query(Device)
        .filter(Device.child_id == child.id, Device.revoked_at.is_(None))
        .all()
    )
    for dev in active_devices:
        await dispatch_device_command(
            db=db,
            device_id=dev.id,
            child_id=child.id,
            command_name="SYNC_POLICY",
            payload={"version": next_version},
            issued_by=current_user.email,
            actor_user_id=current_user.id,
            ip_address=get_client_ip(request),
        )

    return SignedPolicyEnvelope(
        policy=validated_policy,
        updated_at=policy_row.updated_at,
        signature_alg="HMAC-SHA256",
        signature=policy_row.signature,
    )
