"""
F3 Data Retention Worker:
Automatically deletes telemetry `events` and `audit_logs` older than 90 days
(configurable via OGK_RETENTION_DAYS).
"""
from __future__ import annotations

import asyncio
import logging
from datetime import timedelta
from typing import Dict

from sqlalchemy.orm import Session

from ..core.config import settings
from ..core.database import SessionLocal
from ..models.domain import AuditLog, Event, utcnow

logger = logging.getLogger("ogk.retention")


def purge_expired_records(db: Session, retention_days: int | None = None) -> Dict[str, int]:
    """Delete events and audit_logs strictly older than `retention_days`."""
    days = retention_days if retention_days is not None else settings.retention_days
    cutoff = utcnow() - timedelta(days=days)

    deleted_events = (
        db.query(Event)
        .filter(Event.ts < cutoff)
        .delete(synchronize_session=False)
    )
    deleted_audits = (
        db.query(AuditLog)
        .filter(AuditLog.created_at < cutoff)
        .delete(synchronize_session=False)
    )
    db.commit()

    if deleted_events or deleted_audits:
        logger.info(
            "Retention sweep (>%d days): removed %d events and %d audit logs",
            days,
            deleted_events,
            deleted_audits,
        )
    return {
        "events_deleted": int(deleted_events),
        "audit_logs_deleted": int(deleted_audits),
    }


async def retention_background_loop(stop_event: asyncio.Event) -> None:
    """Periodic background task run during FastAPI lifespan."""
    while not stop_event.is_set():
        try:
            db = SessionLocal()
            try:
                purge_expired_records(db)
            finally:
                db.close()
        except Exception:
            logger.exception("Error during 90-day retention sweep")

        try:
            await asyncio.wait_for(
                stop_event.wait(),
                timeout=settings.retention_sweep_interval_seconds,
            )
        except asyncio.TimeoutError:
            continue
