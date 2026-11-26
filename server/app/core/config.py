"""Application configuration loaded from environment variables (.env supported)."""
from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path
from typing import List

from pydantic_settings import BaseSettings, SettingsConfigDict


PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_DB_PATH = PROJECT_ROOT / "server" / "ogk.db"
DATA_DIR = PROJECT_ROOT / "data"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="OGK_",
        env_file=str(PROJECT_ROOT / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "OGK — Companion Parental Control Server"
    environment: str = "development"  # development | production | test
    debug: bool = False

    # SQLite Database
    db_path: str = str(DEFAULT_DB_PATH)

    # Cryptography & Secrets (override via env vars in production!)
    jwt_secret: str = "dev-only-change-me-ogk-jwt-secret-key-2026"
    aes_key_b64: str = ""  # 32-byte base64 key for AES-256-GCM; derived deterministically in dev if empty
    policy_hmac_master_key: str = "dev-only-change-me-ogk-policy-hmac-master"

    # Auth & Session Security (F5)
    cookie_secure: bool = False  # Set True when serving over HTTPS/TLS
    session_cookie_name: str = "ogk_session"
    csrf_cookie_name: str = "ogk_csrf"
    session_ttl_hours: int = 12
    login_max_attempts: int = 5
    login_lockout_minutes: int = 15
    min_password_length: int = 10

    # Device Tokens (F5)
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 30
    pairing_code_expire_minutes: int = 10

    # Protocol & Retention (F3, M6)
    clock_skew_threshold_seconds: int = 120
    retention_days: int = 90
    retention_sweep_interval_seconds: int = 3600

    # Rate Limiting
    rate_limit_requests_per_minute: int = 120
    auth_rate_limit_per_minute: int = 20

    # CORS
    cors_origins: List[str] = ["http://localhost:8000", "http://127.0.0.1:8000"]

    # TLS (optional for uvicorn)
    tls_certfile: str = ""
    tls_keyfile: str = ""

    @property
    def database_url(self) -> str:
        if self.db_path == ":memory:":
            return "sqlite:///:memory:"
        resolved = Path(self.db_path).resolve()
        return f"sqlite:///{resolved.as_posix()}"

    @property
    def aes_key_bytes(self) -> bytes:
        """Return 32-byte AES-256 key from OGK_AES_KEY_B64 or deterministic dev derivation."""
        if self.aes_key_b64:
            raw = base64.b64decode(self.aes_key_b64)
            if len(raw) != 32:
                raise ValueError("OGK_AES_KEY_B64 must decode to exactly 32 bytes for AES-256-GCM")
            return raw
        # Deterministic dev fallback derived from jwt_secret (never hardcode production keys)
        return hashlib.sha256(f"ogk-aes:{self.jwt_secret}".encode("utf-8")).digest()


settings = Settings()
