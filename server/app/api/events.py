"""
Batch Telemetry Ingestion Endpoint (F3 & NT2):
- POST /api/v1/events/batch:
  - Authenticated by device JWT Bearer token
  - Enforces NT2 Data Minimisation (rejects full URLs, file paths, window titles)
  - Deduplicates offline re-transmissions using `idempotency_key`
"""
from __future__ import annotations

from datetime import timezone
from typing import Set

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..core.database import get_db
from ..core.security import get_current_device
from ..models.domain import Device, Event
from ..schemas.payloads import EventBatchRequest, EventBatchResponse

router = APIRouter(prefix="/api/v1/events", tags=["events"])


@router.post("/batch", response_model=EventBatchResponse)
def ingest_events_batch(
    body: EventBatchRequest,
    device: Device = Depends(get_current_device),
    db: Session = Depends(get_db),
) -> EventBatchResponse:
    keys = [item.idempotency_key for item in body.events]
    existing_keys: Set[str] = {
        row[0]
        for row in db.query(Event.idempotency_key)
        .filter(Event.idempotency_key.in_(keys))
        .all()
    }

    seen_in_batch: Set[str] = set()
    accepted = 0
    duplicates_skipped = 0

    for item in body.events:
        if item.idempotency_key in existing_keys or item.idempotency_key in seen_in_batch:
            duplicates_skipped += 1
            continue

        seen_in_batch.add(item.idempotency_key)
        ts_utc = (
            item.ts.replace(tzinfo=timezone.utc)
            if item.ts.tzinfo is None
            else item.ts.astimezone(timezone.utc)
        )
        db.add(
            Event(
                idempotency_key=item.idempotency_key,
                ts=ts_utc,
                device_id=device.id,
                child_id=device.child_id,
                type=item.type.value,
                subject=item.subject.strip().lower(),
                duration_sec=item.duration_sec,
                policy_id=item.policy_id,
            )
        )
        accepted += 1

    if accepted:
        db.commit()

    return EventBatchResponse(accepted=accepted, duplicates_skipped=duplicates_skipped)
