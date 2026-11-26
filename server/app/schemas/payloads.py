"""Pydantic v2 Request & Response schemas for OGK Server API."""
from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator

# Make project root importable so `contracts.shared_schemas` works cleanly
_PROJECT_ROOT = str(Path(__file__).resolve().parents[3])
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from contracts.shared_schemas import (  # noqa: E402
    ChildRequestStatus,
    ChildRequestType,
    PolicyConfigPayload,
    RemoteCommandType,
    SignedPolicyEnvelope,
    TelemetryEventItem,
    is_valid_nt2_subject,
)


# ---------------------------------------------------------------------------
# Auth Schemas
# ---------------------------------------------------------------------------
class LoginRequest(BaseModel):
    email: str = Field(..., min_length=3, max_length=255)
    password: str = Field(..., min_length=1, max_length=256)


class UserSummary(BaseModel):
    id: int
    email: str
    full_name: str
    role: str
    linked_child_id: Optional[int] = None


class ChildSummary(BaseModel):
    id: int
    display_name: str
    age_group: str


class LoginResponse(BaseModel):
    user: UserSummary
    csrf_token: str
    children: List[ChildSummary] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Enrollment Schemas
# ---------------------------------------------------------------------------
class CreatePairingCodeRequest(BaseModel):
    child_id: int


class CreatePairingCodeResponse(BaseModel):
    code: str
    child_id: int
    expires_at: datetime


class EnrollDeviceRequest(BaseModel):
    code: str = Field(..., min_length=8, max_length=16)
    device_name: str = Field(..., min_length=1, max_length=120)
    device_fingerprint: str = Field(..., min_length=8, max_length=256)
    os_version: str = Field(default="Windows 11 x64", max_length=120)


class EnrollDeviceResponse(BaseModel):
    device_id: str
    child_id: int
    access_token: str
    refresh_token: str
    hmac_secret: str
    policy_version: int


class RefreshDeviceTokenRequest(BaseModel):
    device_id: str
    refresh_token: str


class RefreshDeviceTokenResponse(BaseModel):
    device_id: str
    access_token: str
    expires_in_seconds: int


class DeviceSummary(BaseModel):
    id: str
    child_id: int
    device_name: str
    os_version: str
    last_heartbeat_at: Optional[datetime]
    last_policy_version: int
    last_quota_used_sec: int
    tray_visible: bool
    revoked_at: Optional[datetime]


# ---------------------------------------------------------------------------
# Heartbeat Schemas
# ---------------------------------------------------------------------------
class HeartbeatRequest(BaseModel):
    device_id: str
    device_ts: datetime
    policy_version: int = Field(..., ge=0)
    quota_used_seconds: int = Field(default=0, ge=0, le=86400)
    agent_status: str = Field(default="active", max_length=32)
    tray_visible: bool = True


class PendingCommandOut(BaseModel):
    command_id: int
    command: str
    payload: Dict[str, Any] = Field(default_factory=dict)
    issued_by: str
    created_at: datetime


class HeartbeatResponse(BaseModel):
    server_ts: datetime
    clock_skew_detected: bool
    skew_seconds: int
    latest_policy_version: int
    policy_update_required: bool
    pending_commands: List[PendingCommandOut] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Policy Update Schema
# ---------------------------------------------------------------------------
class PolicyUpdateRequest(BaseModel):
    weekday_quota_minutes: int = Field(default=90, ge=0, le=1440)
    weekend_quota_minutes: int = Field(default=120, ge=0, le=1440)
    grace_period_seconds: int = Field(default=60, ge=0, le=300)
    warning_thresholds_minutes: List[int] = Field(default_factory=lambda: [10, 5, 1])
    idle_timeout_seconds: int = Field(default=300, ge=60, le=1800)
    schedule_matrix: List[List[bool]] = Field(
        default_factory=lambda: [[True] * 48 for _ in range(7)]
    )
    enforce_safesearch: bool = True
    block_doh_endpoints: bool = True
    offline_expiry_days: int = Field(default=7, ge=1, le=30)
    offline_expiry_mode: str = Field(default="fail_open_with_education_only")
    blocked_domains: List[Dict[str, Any]] = Field(default_factory=list)
    allowed_domains: List[Dict[str, Any]] = Field(default_factory=list)
    blocked_apps: List[Dict[str, Any]] = Field(default_factory=list)
    allowed_apps: List[Dict[str, Any]] = Field(default_factory=list)
    category_rules: List[Dict[str, Any]] = Field(default_factory=list)
    whitelist_emergency: List[str] = Field(default_factory=list)
    emergency_hotlines: List[str] = Field(default_factory=list)
    change_note: str = Field(default="Cập nhật chính sách", max_length=300)


# ---------------------------------------------------------------------------
# Commands Schema
# ---------------------------------------------------------------------------
class SendCommandRequest(BaseModel):
    command: RemoteCommandType
    payload: Dict[str, Any] = Field(default_factory=dict)


class SendCommandResponse(BaseModel):
    command_id: int
    device_id: str
    command: str
    delivered_via_ws: bool


# ---------------------------------------------------------------------------
# Events Batch Schema
# ---------------------------------------------------------------------------
class EventBatchRequest(BaseModel):
    events: List[TelemetryEventItem] = Field(..., min_length=1, max_length=500)


class EventBatchResponse(BaseModel):
    accepted: int
    duplicates_skipped: int


# ---------------------------------------------------------------------------
# Child Requests Schema (NT3)
# ---------------------------------------------------------------------------
class CreateChildRequestPayload(BaseModel):
    child_id: Optional[int] = None
    request_type: ChildRequestType
    subject: str = Field(..., min_length=1, max_length=253)
    message: str = Field(..., min_length=2, max_length=500)
    requested_minutes: Optional[int] = Field(default=15, ge=5, le=120)

    @field_validator("subject")
    @classmethod
    def validate_subject(cls, v: str) -> str:
        if not is_valid_nt2_subject(v):
            raise ValueError("NT2 violation: subject must be a bare domain, executable name, or short token")
        return v.strip().lower()


class DecisionChildRequestPayload(BaseModel):
    decision: ChildRequestStatus  # approved | rejected
    response_message: str = Field(..., min_length=2, max_length=500)
    grant_minutes: Optional[int] = Field(default=15, ge=5, le=120)

    @field_validator("decision")
    @classmethod
    def validate_decision(cls, v: ChildRequestStatus) -> ChildRequestStatus:
        if v not in (ChildRequestStatus.APPROVED, ChildRequestStatus.REJECTED):
            raise ValueError("decision must be 'approved' or 'rejected'")
        return v


class ChildRequestOut(BaseModel):
    id: int
    child_id: int
    device_id: Optional[str]
    request_type: str
    subject: str
    message: str
    requested_minutes: Optional[int]
    status: str
    parent_response: Optional[str]
    created_at: datetime
    reviewed_at: Optional[datetime]


# ---------------------------------------------------------------------------
# Reports & Audit Log Schemas
# ---------------------------------------------------------------------------
class TopItem(BaseModel):
    subject: str
    total_duration_sec: int
    count: int


class DailyUsagePoint(BaseModel):
    date: str
    total_duration_sec: int
    blocked_count: int


class ReportSummaryResponse(BaseModel):
    child_id: int
    child_name: str
    days: int
    total_duration_sec: int
    total_blocked_events: int
    daily_usage: List[DailyUsagePoint]
    top_apps: List[TopItem]
    top_domains: List[TopItem]
    pending_requests_count: int


class AuditLogOut(BaseModel):
    id: int
    child_id: int
    actor_label: str
    action: str
    ip_address: str
    old_value: Optional[Dict[str, Any]] = None
    new_value: Optional[Dict[str, Any]] = None
    created_at: datetime


class PurgeResponse(BaseModel):
    child_id: int
    events_deleted: int
    requests_deleted: int
    devices_notified: int


__all__ = [
    "PolicyConfigPayload",
    "SignedPolicyEnvelope",
    "TelemetryEventItem",
    "LoginRequest",
    "LoginResponse",
    "UserSummary",
    "ChildSummary",
    "CreatePairingCodeRequest",
    "CreatePairingCodeResponse",
    "EnrollDeviceRequest",
    "EnrollDeviceResponse",
    "RefreshDeviceTokenRequest",
    "RefreshDeviceTokenResponse",
    "DeviceSummary",
    "HeartbeatRequest",
    "HeartbeatResponse",
    "PendingCommandOut",
    "PolicyUpdateRequest",
    "SendCommandRequest",
    "SendCommandResponse",
    "EventBatchRequest",
    "EventBatchResponse",
    "CreateChildRequestPayload",
    "DecisionChildRequestPayload",
    "ChildRequestOut",
    "ReportSummaryResponse",
    "AuditLogOut",
    "PurgeResponse",
]
