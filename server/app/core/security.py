"""
Security primitives for OGK Server (F5):
- Argon2id password hashing + minimum length validation
- AES-256-GCM encryption for sensitive fields (e.g., per-device HMAC secret)
- HMAC-SHA256 policy signing (via shared contracts)
- Server-side session cookies (HttpOnly, Secure, SameSite=Lax) & CSRF protection
- Device JWT (15 min) + Refresh Token (SHA-256 hashed in DB) + RevokedToken checks
- Anti-IDOR ownership guards for `parent`, `child-view`, and `admin`
- Sliding-window IP rate limiter
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Deque, Dict, Optional, Tuple

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import Cookie, Depends, Header, HTTPException, Request, status
from sqlalchemy.orm import Session

from ..core.config import settings
from ..core.database import get_db
from ..models.domain import Child, Device, RevokedToken, User, UserSession, utcnow


# ---------------------------------------------------------------------------
# Argon2id Password Hashing
# ---------------------------------------------------------------------------
_password_hasher = PasswordHasher(
    time_cost=2,
    memory_cost=65536,  # 64 MiB
    parallelism=2,
    hash_len=32,
    salt_len=16,
)


def hash_password(plain_password: str) -> str:
    if len(plain_password) < settings.min_password_length:
        raise ValueError(f"Password must be at least {settings.min_password_length} characters")
    return _password_hasher.hash(plain_password)


def verify_password(plain_password: str, password_hash: str) -> bool:
    try:
        return _password_hasher.verify(password_hash, plain_password)
    except (VerifyMismatchError, InvalidHashError):
        return False


# ---------------------------------------------------------------------------
# AES-256-GCM Encryption for Sensitive Data at Rest
# ---------------------------------------------------------------------------
def encrypt_sensitive(plaintext: str) -> str:
    """Encrypt string with AES-256-GCM; returns base64(nonce || ciphertext || tag)."""
    nonce = os.urandom(12)
    aesgcm = AESGCM(settings.aes_key_bytes)
    ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return base64.b64encode(nonce + ct).decode("ascii")


def decrypt_sensitive(ciphertext_b64: str) -> str:
    """Decrypt base64(nonce || ciphertext || tag) produced by encrypt_sensitive."""
    raw = base64.b64decode(ciphertext_b64.encode("ascii"))
    nonce, ct = raw[:12], raw[12:]
    aesgcm = AESGCM(settings.aes_key_bytes)
    return aesgcm.decrypt(nonce, ct, None).decode("utf-8")


# ---------------------------------------------------------------------------
# Token Hashing & Generation Helpers
# ---------------------------------------------------------------------------
def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def generate_pairing_code(length: int = 8) -> str:
    """Generate unambiguous 8-char uppercase alphanumeric pairing code."""
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def generate_csrf_token() -> str:
    return secrets.token_hex(32)


def generate_opaque_token() -> str:
    return secrets.token_urlsafe(48)


def generate_device_hmac_secret() -> str:
    return secrets.token_hex(32)


def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


# ---------------------------------------------------------------------------
# In-Memory IP Rate Limiter
# ---------------------------------------------------------------------------
class SlidingWindowRateLimiter:
    def __init__(self) -> None:
        self._buckets: Dict[str, Deque[float]] = defaultdict(deque)

    def check(self, key: str, limit: int, window_seconds: int = 60) -> None:
        now = time.monotonic()
        bucket = self._buckets[key]
        cutoff = now - window_seconds
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        if len(bucket) >= limit:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded. Please try again later.",
            )
        bucket.append(now)

    def reset(self) -> None:
        self._buckets.clear()


rate_limiter = SlidingWindowRateLimiter()


# ---------------------------------------------------------------------------
# Device JWT Access Tokens (15 minutes)
# ---------------------------------------------------------------------------
def create_device_access_token(device: Device) -> Tuple[str, str]:
    """Create short-lived (15m) JWT bound to device_id and child_id. Returns (token, jti)."""
    now = utcnow()
    jti = secrets.token_hex(16)
    payload = {
        "sub": device.id,
        "child_id": device.child_id,
        "typ": "device_access",
        "jti": jti,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=settings.access_token_expire_minutes)).timestamp()),
    }
    token = jwt.encode(payload, settings.jwt_secret, algorithm="HS256")
    return token, jti


def decode_device_access_token(token: str, db: Session) -> Device:
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Device access token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid device access token")

    if payload.get("typ") != "device_access":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type")

    jti = payload.get("jti")
    device_id = payload.get("sub")
    if not jti or not device_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Malformed device token")

    # Check revocation list
    revoked = db.query(RevokedToken).filter(RevokedToken.jti == jti).first()
    if revoked is not None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Device token has been revoked")

    device = db.query(Device).filter(Device.id == device_id).first()
    if device is None or device.revoked_at is not None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Device not found or revoked")

    return device


# ---------------------------------------------------------------------------
# FastAPI Auth Dependencies (User Sessions, CSRF, Device Bearer, Anti-IDOR)
# ---------------------------------------------------------------------------
def _ensure_aware(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def create_user_session(user: User, ip_address: str, db: Session) -> Tuple[str, UserSession]:
    raw_token = generate_opaque_token()
    csrf_token = generate_csrf_token()
    session_row = UserSession(
        user_id=user.id,
        token_hash=sha256_hex(raw_token),
        csrf_token=csrf_token,
        ip_address=ip_address,
        expires_at=utcnow() + timedelta(hours=settings.session_ttl_hours),
    )
    db.add(session_row)
    db.commit()
    db.refresh(session_row)
    return raw_token, session_row


def get_current_session_and_user(
    session_cookie: Optional[str] = Cookie(default=None, alias=settings.session_cookie_name),
    db: Session = Depends(get_db),
) -> Tuple[UserSession, User]:
    if not session_cookie:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")

    token_h = sha256_hex(session_cookie)
    session_row = db.query(UserSession).filter(UserSession.token_hash == token_h).first()
    if session_row is None or session_row.revoked_at is not None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session invalid or revoked")

    exp = _ensure_aware(session_row.expires_at)
    if exp is not None and exp < utcnow():
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired")

    user = db.query(User).filter(User.id == session_row.user_id).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    return session_row, user


def get_current_user(
    ctx: Tuple[UserSession, User] = Depends(get_current_session_and_user),
) -> User:
    return ctx[1]


def require_csrf(
    x_csrf_token: Optional[str] = Header(default=None, alias="X-CSRF-Token"),
    ctx: Tuple[UserSession, User] = Depends(get_current_session_and_user),
) -> User:
    """Enforce CSRF protection on every mutating web session request."""
    session_row, user = ctx
    if not x_csrf_token or not hmac.compare_digest(session_row.csrf_token, x_csrf_token):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid or missing CSRF token")
    return user


def get_current_device(
    authorization: Optional[str] = Header(default=None, alias="Authorization"),
    db: Session = Depends(get_db),
) -> Device:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing Bearer device token")
    token = authorization.split(" ", 1)[1].strip()
    return decode_device_access_token(token, db)


def get_optional_user_or_device(
    authorization: Optional[str] = Header(default=None, alias="Authorization"),
    session_cookie: Optional[str] = Cookie(default=None, alias=settings.session_cookie_name),
    db: Session = Depends(get_db),
) -> Tuple[Optional[User], Optional[Device]]:
    """Allow endpoints accessible by either a logged-in User OR an authenticated Device."""
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()
        return None, decode_device_access_token(token, db)
    if session_cookie:
        _, user = get_current_session_and_user(session_cookie=session_cookie, db=db)
        return user, None
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")


# ---------------------------------------------------------------------------
# Anti-IDOR Ownership Guards (Query-level authorization — NEVER trust client IDs)
# ---------------------------------------------------------------------------
def get_authorized_child(
    child_id: int,
    user: User,
    db: Session,
    allow_child_view: bool = True,
) -> Child:
    """
    Query-level anti-IDOR check:
    - parent: child.parent_id == user.id
    - child-view: allow_child_view and child.id == user.linked_child_id
    - admin: allowed
    """
    child = db.query(Child).filter(Child.id == child_id).first()
    if child is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Child profile not found")

    if user.role == "admin":
        return child
    if user.role == "parent" and child.parent_id == user.id:
        return child
    if user.role == "child-view" and allow_child_view and user.linked_child_id == child.id:
        return child

    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Forbidden: you do not have permission to access this child profile",
    )


def get_authorized_device(
    device_id: str,
    user: User,
    db: Session,
    allow_child_view: bool = False,
) -> Device:
    """Query-level anti-IDOR check on device_id via its owning Child."""
    device = db.query(Device).filter(Device.id == device_id).first()
    if device is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    get_authorized_child(device.child_id, user, db, allow_child_view=allow_child_view)
    return device


def require_parent_csrf(user: User = Depends(require_csrf)) -> User:
    if user.role not in ("parent", "admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only parent or admin accounts may perform this action",
        )
    return user
