"""
Transparent Reporting, Audit Logs, Export (CSV/PDF), and Right-to-Erasure Purge (F3 & NT5):
- GET    /api/v1/reports/{child_id}/summary?days=7   (parent & child-view)
- GET    /api/v1/reports/{child_id}/audit-logs       (parent & child-view per NT5)
- GET    /api/v1/reports/{child_id}/export?format=csv|pdf
- DELETE /api/v1/reports/{child_id}/purge            (parent only + CSRF; clears server & notifies agents)
"""
from __future__ import annotations

import csv
import io
import json
from collections import defaultdict
from datetime import timedelta
from typing import Dict, List

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from sqlalchemy.orm import Session

from ..core.database import get_db
from ..core.security import (
    get_authorized_child,
    get_client_ip,
    get_current_user,
    require_parent_csrf,
)
from ..models.domain import AuditLog, ChildRequest, Device, Event, User, utcnow
from ..schemas.payloads import (
    AuditLogOut,
    DailyUsagePoint,
    PurgeResponse,
    ReportSummaryResponse,
    TopItem,
)
from .ws import dispatch_device_command

router = APIRouter(prefix="/api/v1/reports", tags=["reports & transparency"])


def _build_report_summary(child_id: int, child_name: str, days: int, db: Session) -> ReportSummaryResponse:
    cutoff = utcnow() - timedelta(days=days)
    events = (
        db.query(Event)
        .filter(Event.child_id == child_id, Event.ts >= cutoff)
        .order_by(Event.ts.asc())
        .all()
    )

    daily_duration: Dict[str, int] = defaultdict(int)
    daily_blocked: Dict[str, int] = defaultdict(int)
    app_totals: Dict[str, List[int]] = defaultdict(lambda: [0, 0])  # [duration, count]
    domain_totals: Dict[str, List[int]] = defaultdict(lambda: [0, 0])
    total_duration = 0
    total_blocked = 0

    for ev in events:
        day_key = ev.ts.strftime("%Y-%m-%d")
        daily_duration[day_key] += ev.duration_sec
        total_duration += ev.duration_sec

        if ev.type in ("blocked_app", "blocked_domain"):
            daily_blocked[day_key] += 1
            total_blocked += 1

        if ev.type in ("app_start", "app_stop", "blocked_app"):
            app_totals[ev.subject][0] += ev.duration_sec
            app_totals[ev.subject][1] += 1
        elif ev.type in ("domain_query", "blocked_domain"):
            domain_totals[ev.subject][0] += ev.duration_sec
            domain_totals[ev.subject][1] += 1

    today = utcnow().date()
    daily_points: List[DailyUsagePoint] = []
    for offset in range(days - 1, -1, -1):
        d_str = (today - timedelta(days=offset)).isoformat()
        daily_points.append(
            DailyUsagePoint(
                date=d_str,
                total_duration_sec=daily_duration.get(d_str, 0),
                blocked_count=daily_blocked.get(d_str, 0),
            )
        )

    top_apps = [
        TopItem(subject=subj, total_duration_sec=vals[0], count=vals[1])
        for subj, vals in sorted(app_totals.items(), key=lambda kv: (-kv[1][0], -kv[1][1]))[:10]
    ]
    top_domains = [
        TopItem(subject=subj, total_duration_sec=vals[0], count=vals[1])
        for subj, vals in sorted(domain_totals.items(), key=lambda kv: (-kv[1][1], -kv[1][0]))[:10]
    ]

    pending_requests_count = (
        db.query(ChildRequest)
        .filter(ChildRequest.child_id == child_id, ChildRequest.status == "pending")
        .count()
    )

    return ReportSummaryResponse(
        child_id=child_id,
        child_name=child_name,
        days=days,
        total_duration_sec=total_duration,
        total_blocked_events=total_blocked,
        daily_usage=daily_points,
        top_apps=top_apps,
        top_domains=top_domains,
        pending_requests_count=pending_requests_count,
    )


def _generate_minimal_pdf(lines: List[str]) -> bytes:
    """
    Generate a valid standalone PDF 1.4 document with zero external binary deps.
    Uses standard built-in Helvetica font and ASCII-safe transliteration for portability.
    """
    def _escape_pdf_text(text: str) -> str:
        ascii_text = text.encode("ascii", "replace").decode("ascii")
        return ascii_text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

    content_ops = ["BT", "/F1 11 Tf", "50 760 Td", "16 TL"]
    for idx, line in enumerate(lines[:42]):
        escaped = _escape_pdf_text(line)
        if idx == 0:
            content_ops.append(f"({escaped}) Tj")
        else:
            content_ops.append(f"T* ({escaped}) Tj")
    content_ops.append("ET")
    stream_bytes = "\n".join(content_ops).encode("latin-1")

    objects = [
        b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n",
        b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n",
        b"3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >> endobj\n",
        b"4 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj\n",
        f"5 0 obj << /Length {len(stream_bytes)} >> stream\n".encode("ascii")
        + stream_bytes
        + b"\nendstream endobj\n",
    ]

    buf = io.BytesIO()
    buf.write(b"%PDF-1.4\n")
    offsets = [0]
    for obj in objects:
        offsets.append(buf.tell())
        buf.write(obj)

    xref_pos = buf.tell()
    buf.write(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    buf.write(b"0000000000 65535 f \n")
    for off in offsets[1:]:
        buf.write(f"{off:010d} 00000 n \n".encode("ascii"))

    buf.write(
        f"trailer << /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n".encode("ascii")
    )
    return buf.getvalue()


@router.get("/{child_id}/summary", response_model=ReportSummaryResponse)
def get_usage_summary(
    child_id: int,
    days: int = Query(default=7, ge=1, le=90),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ReportSummaryResponse:
    child = get_authorized_child(child_id, current_user, db, allow_child_view=True)
    return _build_report_summary(child.id, child.display_name, days, db)


@router.get("/{child_id}/audit-logs", response_model=List[AuditLogOut])
def get_audit_logs(
    child_id: int,
    limit: int = Query(default=100, ge=1, le=500),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> List[AuditLogOut]:
    """NT5: Both parent and child-view can inspect the policy/action audit log."""
    child = get_authorized_child(child_id, current_user, db, allow_child_view=True)
    rows = (
        db.query(AuditLog)
        .filter(AuditLog.child_id == child.id)
        .order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
        .limit(limit)
        .all()
    )
    return [
        AuditLogOut(
            id=r.id,
            child_id=r.child_id,
            actor_label=r.actor_label,
            action=r.action,
            ip_address=r.ip_address,
            old_value=json.loads(r.old_value_json) if r.old_value_json else None,
            new_value=json.loads(r.new_value_json) if r.new_value_json else None,
            created_at=r.created_at,
        )
        for r in rows
    ]


@router.get("/{child_id}/export")
def export_report(
    child_id: int,
    format: str = Query(default="csv", pattern="^(csv|pdf)$"),
    days: int = Query(default=7, ge=1, le=90),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Response:
    child = get_authorized_child(child_id, current_user, db, allow_child_view=True)
    summary = _build_report_summary(child.id, child.display_name, days, db)

    if format == "csv":
        out = io.StringIO()
        writer = csv.writer(out)
        writer.writerow(["section", "name_or_date", "duration_sec", "count_or_blocked"])
        for d in summary.daily_usage:
            writer.writerow(["daily_usage", d.date, d.total_duration_sec, d.blocked_count])
        for app in summary.top_apps:
            writer.writerow(["top_app", app.subject, app.total_duration_sec, app.count])
        for dom in summary.top_domains:
            writer.writerow(["top_domain", dom.subject, dom.total_duration_sec, dom.count])
        return Response(
            content=out.getvalue(),
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="ogk_report_child_{child.id}.csv"'},
        )

    lines = [
        f"OGK Companion Usage Report - Child ID: {child.id} ({summary.days} days)",
        f"Generated UTC: {utcnow().isoformat()}",
        f"Total Duration (sec): {summary.total_duration_sec} | Blocked Events: {summary.total_blocked_events}",
        "------------------------------------------------------------",
        "Daily Usage:",
    ]
    for d in summary.daily_usage:
        lines.append(f"  {d.date}: {d.total_duration_sec}s | blocked={d.blocked_count}")
    lines.append("Top Apps:")
    for app in summary.top_apps:
        lines.append(f"  {app.subject}: {app.total_duration_sec}s (count={app.count})")
    lines.append("Top Domains:")
    for dom in summary.top_domains:
        lines.append(f"  {dom.subject}: count={dom.count}")

    pdf_bytes = _generate_minimal_pdf(lines)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="ogk_report_child_{child.id}.pdf"'},
    )


@router.delete("/{child_id}/purge", response_model=PurgeResponse)
async def purge_child_data(
    child_id: int,
    request: Request,
    current_user: User = Depends(require_parent_csrf),
    db: Session = Depends(get_db),
) -> PurgeResponse:
    """
    F3 Right-to-Erasure ('Xóa toàn bộ dữ liệu của con tôi'):
    Deletes all telemetry events and requests for `child_id` on server
    and dispatches `PURGE_CACHE` to all active devices of this child.
    """
    child = get_authorized_child(child_id, current_user, db, allow_child_view=False)

    events_deleted = db.query(Event).filter(Event.child_id == child.id).delete(synchronize_session=False)
    requests_deleted = (
        db.query(ChildRequest).filter(ChildRequest.child_id == child.id).delete(synchronize_session=False)
    )
    db.add(
        AuditLog(
            child_id=child.id,
            actor_user_id=current_user.id,
            actor_label=current_user.email,
            action="DATA_PURGED_BY_PARENT",
            ip_address=get_client_ip(request),
            new_value_json=json.dumps(
                {"events_deleted": int(events_deleted), "requests_deleted": int(requests_deleted)}
            ),
        )
    )
    db.commit()

    active_devices = (
        db.query(Device)
        .filter(Device.child_id == child.id, Device.revoked_at.is_(None))
        .all()
    )
    for dev in active_devices:
        await dispatch_device_command(
            db=db,
            device_id=dev.id,
            child_id=child.id,
            command_name="PURGE_CACHE",
            payload={"reason": "parent_requested_full_purge"},
            issued_by=current_user.email,
            actor_user_id=current_user.id,
            ip_address=get_client_ip(request),
        )

    return PurgeResponse(
        child_id=child.id,
        events_deleted=int(events_deleted),
        requests_deleted=int(requests_deleted),
        devices_notified=len(active_devices),
    )
