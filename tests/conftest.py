"""Pytest fixtures providing isolated SQLite WAL databases and FastAPI TestClient."""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Dict

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(PROJECT_ROOT / "server") not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT / "server"))

from contracts.shared_schemas import PolicyConfigPayload, sign_policy_payload  # noqa: E402
from server.app.core.config import DATA_DIR, settings  # noqa: E402
from server.app.core.database import Base, create_sqlite_engine, get_db  # noqa: E402
from server.app.core.security import hash_password, rate_limiter  # noqa: E402
from server.app.main import app  # noqa: E402
from server.app.models.domain import Child, Policy, User, utcnow  # noqa: E402


@pytest.fixture()
def db_session(tmp_path):
    settings.environment = "test"
    rate_limiter.reset()

    db_file = tmp_path / "ogk_test.db"
    engine = create_sqlite_engine(f"sqlite:///{db_file.as_posix()}")
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)

    session = TestingSessionLocal()
    try:
        yield session, TestingSessionLocal
    finally:
        session.close()
        engine.dispose()


@pytest.fixture()
def client(db_session):
    _session, TestingSessionLocal = db_session

    def _override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = _override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture()
def seeded_actors(db_session) -> Dict[str, object]:
    """Create Parent 1 (+ Child 1 + Child-View 1) and Parent 2 (+ Child 2) with signed policies."""
    db, _ = db_session

    parent1 = User(
        email="parent1@ogk.test",
        full_name="Parent One",
        password_hash=hash_password("ParentOnePass123!"),
        role="parent",
    )
    parent2 = User(
        email="parent2@ogk.test",
        full_name="Parent Two",
        password_hash=hash_password("ParentTwoPass123!"),
        role="parent",
    )
    db.add_all([parent1, parent2])
    db.commit()
    db.refresh(parent1)
    db.refresh(parent2)

    child1 = Child(parent_id=parent1.id, display_name="Child One", age_group="6-11")
    child2 = Child(parent_id=parent2.id, display_name="Child Two", age_group="6-11")
    db.add_all([child1, child2])
    db.commit()
    db.refresh(child1)
    db.refresh(child2)

    child_view1 = User(
        email="child1@ogk.test",
        full_name="Child One View",
        password_hash=hash_password("ChildViewPass123!"),
        role="child-view",
        linked_child_id=child1.id,
    )
    db.add(child_view1)
    db.commit()
    db.refresh(child_view1)

    tpl = json.loads((DATA_DIR / "default_policy_6_11.json").read_text(encoding="utf-8"))
    tpl.pop("profile_name", None)

    for child, parent in ((child1, parent1), (child2, parent2)):
        cfg = dict(tpl)
        cfg["child_id"] = child.id
        cfg["version"] = 1
        policy_obj = PolicyConfigPayload.model_validate(cfg)
        db.add(
            Policy(
                child_id=child.id,
                version=1,
                config_json=json.dumps(
                    policy_obj.model_dump(mode="json"),
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                ),
                signature=sign_policy_payload(policy_obj, settings.policy_hmac_master_key),
                updated_by_user_id=parent.id,
                updated_at=utcnow(),
            )
        )
    db.commit()

    return {
        "parent1": parent1,
        "parent2": parent2,
        "child1": child1,
        "child2": child2,
        "child_view1": child_view1,
        "parent1_password": "ParentOnePass123!",
        "parent2_password": "ParentTwoPass123!",
        "child_view1_password": "ChildViewPass123!",
    }


def login_helper(client: TestClient, email: str, password: str) -> dict:
    resp = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert resp.status_code == 200, resp.text
    return resp.json()


def enroll_device_helper(client: TestClient, child_id: int, csrf_token: str, device_name: str = "KID-PC") -> dict:
    code_resp = client.post(
        "/api/v1/enroll/code",
        json={"child_id": child_id},
        headers={"X-CSRF-Token": csrf_token},
    )
    assert code_resp.status_code == 201, code_resp.text
    code = code_resp.json()["code"]

    enroll_resp = client.post(
        "/api/v1/enroll/device",
        json={
            "code": code,
            "device_name": device_name,
            "device_fingerprint": f"fp-{device_name}-abcdef123456",
            "os_version": "Windows 11 x64",
        },
    )
    assert enroll_resp.status_code == 201, enroll_resp.text
    return enroll_resp.json()
