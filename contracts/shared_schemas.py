"""
OGK Shared Schemas, Canonical Policy Signing (HMAC-SHA256), and NT2/NT6 Validators.

Imported by BOTH `/server` and `/agent` so both sides enforce the exact same
data contracts, NT2 Data Minimisation rules, NT4 Explainability fields,
NT6 Emergency Whitelist, and cryptographic policy integrity verification.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator, model_validator


# ---------------------------------------------------------------------------
# NT6: Immutable Emergency & Child-Safety Whitelist (NEVER blockable)
# ---------------------------------------------------------------------------
NT6_EMERGENCY_HOTLINES: tuple[str, ...] = ("111", "113", "114", "115")

NT6_IMMUTABLE_WHITELIST_DOMAINS: tuple[str, ...] = (
    "tongdai111.vn",
    "111.gov.vn",
    "moet.gov.vn",
    "chinhphu.vn",
    "moh.gov.vn",
    "bocongan.gov.vn",
    "edu.vn",
    "vnedu.vn",
    "olm.vn",
    "vio.edu.vn",
)

NT6_IMMUTABLE_WHITELIST_APPS: tuple[str, ...] = (
    "explorer.exe",
    "taskmgr.exe",
    "ogk-tray.exe",
    "ogk-service.exe",
)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------
class UserRole(str, Enum):
    PARENT = "parent"
    CHILD_VIEW = "child-view"
    ADMIN = "admin"


class EventType(str, Enum):
    APP_START = "app_start"
    APP_STOP = "app_stop"
    DOMAIN_QUERY = "domain_query"
    BLOCKED_APP = "blocked_app"
    BLOCKED_DOMAIN = "blocked_domain"
    QUOTA_WARNING = "quota_warning"
    LOCKED = "locked"
    UNLOCK_REQUEST = "unlock_request"
    OVERRIDE_GRANTED = "override_granted"


class DomainCategoryEnum(str, Enum):
    EDUCATION = "education"
    ENTERTAINMENT = "entertainment"
    SOCIAL_MEDIA = "social_media"
    GAMING = "gaming"
    AGE_INAPPROPRIATE = "age_inappropriate"
    UNCATEGORIZED = "uncategorized"


class ChildRequestType(str, Enum):
    UNLOCK_REQUEST = "unlock_request"
    FALSE_POSITIVE_REPORT = "false_positive_report"


class ChildRequestStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class RemoteCommandType(str, Enum):
    LOCK_NOW = "LOCK_NOW"
    UNLOCK_NOW = "UNLOCK_NOW"
    ADD_15M = "ADD_15M"
    PURGE_CACHE = "PURGE_CACHE"
    PAUSE_2H = "PAUSE_2H"
    SYNC_POLICY = "SYNC_POLICY"


# ---------------------------------------------------------------------------
# NT2 Data Minimisation Validators
# ---------------------------------------------------------------------------
_DOMAIN_REGEX = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)
_EXECUTABLE_REGEX = re.compile(r"^[a-zA-Z0-9._-]{1,120}\.(exe|msi|bat|cmd|ps1|app)$", re.IGNORECASE)
_SYSTEM_SUBJECT_REGEX = re.compile(r"^[a-z0-9_.:-]{1,64}$")

_FORBIDDEN_URL_MARKERS = (
    "http://",
    "https://",
    "ftp://",
    "ws://",
    "wss://",
    "/",
    "\\",
    "?",
    "&",
    "=",
    "#",
    "@",
    " ",
)


def is_valid_nt2_subject(subject: str, event_type: Optional[EventType] = None) -> bool:
    """
    Validate that `subject` obeys NT2 (Data Minimisation):
    - NEVER a full URL (no scheme, path, query string, fragment, credentials, spaces)
    - NEVER a window title or file path
    - For domain events: bare lowercase domain (second-level or safe host without path)
    - For app events: bare executable filename (e.g. chrome.exe), not a full filesystem path
    - For system/quota events: compact token (e.g. daily_quota, schedule_lock)
    """
    if not subject or len(subject) > 253:
        return False

    lowered = subject.lower()
    for marker in _FORBIDDEN_URL_MARKERS:
        if marker in lowered:
            return False

    if event_type in (EventType.DOMAIN_QUERY, EventType.BLOCKED_DOMAIN):
        return bool(_DOMAIN_REGEX.match(lowered))

    if event_type in (EventType.APP_START, EventType.APP_STOP, EventType.BLOCKED_APP):
        return bool(_EXECUTABLE_REGEX.match(subject))

    # Generic fallback for quota_warning, locked, unlock_request, override_granted
    return bool(
        _DOMAIN_REGEX.match(lowered)
        or _EXECUTABLE_REGEX.match(subject)
        or _SYSTEM_SUBJECT_REGEX.match(lowered)
    )


def normalize_second_level_domain(domain: str) -> str:
    """Normalize a hostname to lowercase bare domain (no trailing dot)."""
    cleaned = domain.strip().lower().rstrip(".")
    if any(m in cleaned for m in _FORBIDDEN_URL_MARKERS):
        raise ValueError(f"NT2 violation: full URL or path is forbidden: {domain!r}")
    if not _DOMAIN_REGEX.match(cleaned):
        raise ValueError(f"Invalid domain format: {domain!r}")
    return cleaned


def is_nt6_protected_domain(domain: str) -> bool:
    """Return True if `domain` or its parent suffix is protected under NT6."""
    d = domain.strip().lower().rstrip(".")
    for safe in NT6_IMMUTABLE_WHITELIST_DOMAINS:
        if d == safe or d.endswith("." + safe):
            return True
    return False


# ---------------------------------------------------------------------------
# Policy Sub-Models (Shared between Server and Agent)
# ---------------------------------------------------------------------------
class RuleItem(BaseModel):
    """NT4: Every block/allow rule MUST include `reason` and `created_by`."""
    target: str = Field(..., min_length=1, max_length=253, description="Domain or executable name")
    sha256: Optional[str] = Field(
        default=None,
        min_length=64,
        max_length=64,
        description="Optional SHA-256 hash of executable for anti-rename verification",
    )
    reason: str = Field(..., min_length=3, max_length=300, description="NT4: Human-readable reason")
    created_by: str = Field(..., min_length=1, max_length=120, description="NT4: Who created this rule")

    @field_validator("target")
    @classmethod
    def validate_target_nt2(cls, v: str) -> str:
        v = v.strip().lower()
        for marker in _FORBIDDEN_URL_MARKERS:
            if marker in v:
                raise ValueError(f"NT2 violation: rule target must not be a full URL or path ({v!r})")
        return v


class CategoryBudget(BaseModel):
    category: DomainCategoryEnum
    daily_limit_minutes: Optional[int] = Field(
        default=None, ge=0, le=1440, description="None = unlimited"
    )
    blocked: bool = False
    reason: str = Field(..., min_length=3, max_length=300)
    created_by: str = Field(..., min_length=1, max_length=120)


class PolicyConfigPayload(BaseModel):
    """
    Canonical policy configuration signed by Server with HMAC-SHA256
    and verified by Agent before enforcement.
    """
    child_id: int
    version: int = Field(..., ge=1)
    weekday_quota_minutes: int = Field(default=90, ge=0, le=1440)
    weekend_quota_minutes: int = Field(default=120, ge=0, le=1440)
    grace_period_seconds: int = Field(default=60, ge=0, le=300)
    warning_thresholds_minutes: List[int] = Field(default_factory=lambda: [10, 5, 1])
    idle_timeout_seconds: int = Field(default=300, ge=60, le=1800)
    # 7 days (Mon=0 .. Sun=6) x 48 half-hour slots (True = allowed, False = locked)
    schedule_matrix: List[List[bool]] = Field(
        default_factory=lambda: [[True] * 48 for _ in range(7)]
    )
    enforce_safesearch: bool = True
    block_doh_endpoints: bool = True
    offline_expiry_days: int = Field(default=7, ge=1, le=30)
    offline_expiry_mode: str = Field(
        default="fail_open_with_education_only",
        description="Explicit offline fallback policy after N days without server sync",
    )
    blocked_domains: List[RuleItem] = Field(default_factory=list)
    allowed_domains: List[RuleItem] = Field(default_factory=list)
    blocked_apps: List[RuleItem] = Field(default_factory=list)
    allowed_apps: List[RuleItem] = Field(default_factory=list)
    category_rules: List[CategoryBudget] = Field(default_factory=list)
    whitelist_emergency: List[str] = Field(
        default_factory=lambda: list(NT6_IMMUTABLE_WHITELIST_DOMAINS)
    )
    emergency_hotlines: List[str] = Field(
        default_factory=lambda: list(NT6_EMERGENCY_HOTLINES)
    )

    @field_validator("schedule_matrix")
    @classmethod
    def validate_schedule_matrix(cls, v: List[List[bool]]) -> List[List[bool]]:
        if len(v) != 7 or any(len(day) != 48 for day in v):
            raise ValueError("schedule_matrix must be exactly 7x48 booleans (7 days x 30-min slots)")
        return v

    @model_validator(mode="after")
    def enforce_nt6_invariants(self) -> "PolicyConfigPayload":
        # NT6: Emergency whitelist cannot be removed or overridden into blocked_domains
        for item in self.blocked_domains:
            if is_nt6_protected_domain(item.target):
                raise ValueError(
                    f"NT6 violation: emergency/safety domain {item.target!r} cannot be blocked"
                )
        for item in self.blocked_apps:
            if item.target.lower() in NT6_IMMUTABLE_WHITELIST_APPS:
                raise ValueError(
                    f"NT6 violation: essential system/transparency app {item.target!r} cannot be blocked"
                )
        # Ensure all immutable NT6 domains and hotlines are always present
        merged_whitelist = list(dict.fromkeys(list(NT6_IMMUTABLE_WHITELIST_DOMAINS) + self.whitelist_emergency))
        merged_hotlines = list(dict.fromkeys(list(NT6_EMERGENCY_HOTLINES) + self.emergency_hotlines))
        self.whitelist_emergency = merged_whitelist
        self.emergency_hotlines = merged_hotlines
        return self


class SignedPolicyEnvelope(BaseModel):
    """Policy envelope transmitted over HTTPS and cached in Agent local SQLite."""
    policy: PolicyConfigPayload
    updated_at: datetime
    signature_alg: str = "HMAC-SHA256"
    signature: str = Field(..., min_length=64, max_length=64)


# ---------------------------------------------------------------------------
# Event Schema (Shared between Agent batch sync and Server ingestion)
# ---------------------------------------------------------------------------
class TelemetryEventItem(BaseModel):
    """
    F3 & NT2 compliant event schema.
    Strictly restricted to: ts, device_id, child_id, type, subject, duration_sec, policy_id
    plus idempotency_key for offline batch deduplication.
    """
    idempotency_key: str = Field(..., min_length=8, max_length=128)
    ts: datetime
    device_id: Optional[str] = None
    child_id: Optional[int] = None
    type: EventType
    subject: str = Field(..., min_length=1, max_length=253)
    duration_sec: int = Field(default=0, ge=0, le=86400)
    policy_id: Optional[int] = None

    @model_validator(mode="after")
    def validate_subject_nt2(self) -> "TelemetryEventItem":
        if not is_valid_nt2_subject(self.subject, self.type):
            raise ValueError(
                f"NT2 Data Minimisation violation: invalid subject {self.subject!r} "
                f"for event type {self.type.value!r}. Full URLs, paths, and window titles are forbidden."
            )
        return self


# ---------------------------------------------------------------------------
# Local IPC Schema (Service <-> Tray UI over Named Pipe / 127.0.0.1)
# ---------------------------------------------------------------------------
class LocalIPCBlockNotice(BaseModel):
    """Sent from Windows Service to Tray UI when an app/domain is blocked (NT4)."""
    kind: str = Field(..., pattern="^(app|domain|quota|schedule)$")
    subject: str
    reason: str
    created_by: str
    occurred_at: datetime
    can_request_unlock: bool = True
    can_report_false_positive: bool = True


class LocalIPCStatusResponse(BaseModel):
    """Returned by Windows Service to Tray UI for the child's status display (NT1/NT5)."""
    service_running: bool = True
    device_id: str
    child_name: str
    policy_version: int
    quota_used_seconds: int
    quota_limit_seconds: int
    quota_remaining_seconds: int
    is_locked: bool
    lock_reason: Optional[str] = None
    in_grace_period: bool = False
    grace_remaining_seconds: int = 0
    offline_mode: bool = False
    last_sync_ts: Optional[datetime] = None


# ---------------------------------------------------------------------------
# Canonical JSON & HMAC-SHA256 Signing / Verification
# ---------------------------------------------------------------------------
def canonical_json_bytes(data: Dict[str, Any]) -> bytes:
    """Serialize dict deterministically for HMAC-SHA256 signing."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sign_policy_payload(policy: PolicyConfigPayload | Dict[str, Any], secret: str) -> str:
    """Compute hex-encoded HMAC-SHA256 over canonical policy JSON."""
    if isinstance(policy, PolicyConfigPayload):
        payload_dict = policy.model_dump(mode="json")
    else:
        payload_dict = policy
    digest = hmac.new(
        secret.encode("utf-8"),
        canonical_json_bytes(payload_dict),
        hashlib.sha256,
    ).hexdigest()
    return digest


def verify_policy_signature(
    policy: PolicyConfigPayload | Dict[str, Any],
    signature: str,
    secret: str,
) -> bool:
    """
    Constant-time HMAC-SHA256 verification.
    Agent MUST call this before applying any downloaded or cached policy.
    """
    if not signature or not secret:
        return False
    expected = sign_policy_payload(policy, secret)
    return hmac.compare_digest(expected, signature.strip().lower())
