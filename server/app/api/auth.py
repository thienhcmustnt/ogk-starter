"""
Authentication & Session Endpoints (F5):
- POST /api/v1/auth/login: Argon2id verification, 5-attempt / 15-min lockout, IP rate limit,
  HttpOnly + SameSite=Lax cookie + CSRF token
- POST /api/v1/auth/logout: Server-side session revocation + CSRF verification
- GET  /api/v1/auth/me: Current user, CSRF token, and authorized children
"""
from __future__ import annotations

from datetime import timedelta, timezone
from typing import Tuple

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from ..core.config import settings
from ..core.database import get_db
from ..core.security import (
    create_user_session,
    get_client_ip,
    get_current_session_and_user,
    rate_limiter,
    require_csrf,
    verify_password,
)
from ..models.domain import Child, User, UserSession, utcnow
from ..schemas.payloads import ChildSummary, LoginRequest, LoginResponse, UserSummary

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


def _children_for_user(user: User, db: Session) -> list[ChildSummary]:
    if user.role == "admin":
        rows = db.query(Child).order_by(Child.id.asc()).all()
    elif user.role == "parent":
        rows = db.query(Child).filter(Child.parent_id == user.id).order_by(Child.id.asc()).all()
    elif user.role == "child-view" and user.linked_child_id is not None:
        rows = db.query(Child).filter(Child.id == user.linked_child_id).all()
    else:
        rows = []
    return [ChildSummary(id=c.id, display_name=c.display_name, age_group=c.age_group) for c in rows]


@router.post("/login", response_model=LoginResponse)
def login(
    body: LoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> LoginResponse:
    ip = get_client_ip(request)
    rate_limiter.check(f"login:{ip}", limit=settings.auth_rate_limit_per_minute, window_seconds=60)

    user = db.query(User).filter(User.email == body.email.strip().lower()).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    now = utcnow()
    if user.locked_until is not None:
        locked_until = (
            user.locked_until.replace(tzinfo=timezone.utc)
            if user.locked_until.tzinfo is None
            else user.locked_until
        )
        if locked_until > now:
            remaining_sec = int((locked_until - now).total_seconds())
            raise HTTPException(
                status_code=status.HTTP_423_LOCKED,
                detail=f"Account temporarily locked due to failed logins. Retry in {remaining_sec} seconds.",
            )
        # Lockout expired -> reset counter
        user.locked_until = None
        user.failed_login_attempts = 0
        db.commit()

    if not verify_password(body.password, user.password_hash):
        user.failed_login_attempts += 1
        if user.failed_login_attempts >= settings.login_max_attempts:
            user.locked_until = now + timedelta(minutes=settings.login_lockout_minutes)
        db.commit()
        if user.locked_until is not None:
            raise HTTPException(
                status_code=status.HTTP_423_LOCKED,
                detail=f"Too many failed login attempts. Account locked for {settings.login_lockout_minutes} minutes.",
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    # Successful login -> reset failure counters and issue server-side session
    user.failed_login_attempts = 0
    user.locked_until = None
    db.commit()

    raw_session_token, session_row = create_user_session(user=user, ip_address=ip, db=db)

    max_age = settings.session_ttl_hours * 3600
    response.set_cookie(
        key=settings.session_cookie_name,
        value=raw_session_token,
        max_age=max_age,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="lax",
        path="/",
    )
    response.set_cookie(
        key=settings.csrf_cookie_name,
        value=session_row.csrf_token,
        max_age=max_age,
        httponly=False,
        secure=settings.cookie_secure,
        samesite="lax",
        path="/",
    )

    return LoginResponse(
        user=UserSummary(
            id=user.id,
            email=user.email,
            full_name=user.full_name,
            role=user.role,
            linked_child_id=user.linked_child_id,
        ),
        csrf_token=session_row.csrf_token,
        children=_children_for_user(user, db),
    )


@router.post("/logout")
def logout(
    response: Response,
    _csrf_user: User = Depends(require_csrf),
    ctx: Tuple[UserSession, User] = Depends(get_current_session_and_user),
    db: Session = Depends(get_db),
) -> dict:
    session_row, _ = ctx
    session_row.revoked_at = utcnow()
    db.commit()

    response.delete_cookie(key=settings.session_cookie_name, path="/")
    response.delete_cookie(key=settings.csrf_cookie_name, path="/")
    return {"status": "logged_out"}


@router.get("/me", response_model=LoginResponse)
def me(
    ctx: Tuple[UserSession, User] = Depends(get_current_session_and_user),
    db: Session = Depends(get_db),
) -> LoginResponse:
    session_row, user = ctx
    return LoginResponse(
        user=UserSummary(
            id=user.id,
            email=user.email,
            full_name=user.full_name,
            role=user.role,
            linked_child_id=user.linked_child_id,
        ),
        csrf_token=session_row.csrf_token,
        children=_children_for_user(user, db),
    )
