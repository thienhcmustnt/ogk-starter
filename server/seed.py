"""
Seed Script for OGK Server:
- Initializes SQLite database (WAL + foreign_keys)
- Loads 220+ safe categorized domains + DoH lists + NT6 whitelist from data/domain_categories.json
- Creates demo accounts (parent, parent2, child-view, admin)
- Creates demo child profiles and default 6-11 signed policies from data/default_policy_6_11.json
- Inserts sample NT2-compliant telemetry events and initial audit logs

Run:
    python server/seed.py
"""
from __future__ import annotations

import json
import sys
from datetime import timedelta
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(PROJECT_ROOT / "server") not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT / "server"))

from contracts.shared_schemas import PolicyConfigPayload, sign_policy_payload  # noqa: E402
from server.app.core.config import DATA_DIR, settings  # noqa: E402
from server.app.core.database import SessionLocal, init_db  # noqa: E402
from server.app.core.security import encrypt_sensitive, hash_password, sha256_hex  # noqa: E402
from server.app.models.domain import (  # noqa: E402
    AuditLog,
    Child,
    ChildRequest,
    Device,
    DomainCategory,
    Event,
    Policy,
    User,
    utcnow,
)


DEMO_ACCOUNTS = {
    "parent": ("parent@ogk.local", "ParentPass2026!", "Phụ huynh Minh Anh"),
    "parent2": ("parent2@ogk.local", "ParentTwoPass2026!", "Phụ huynh Gia Bảo"),
    "child_view": ("child@ogk.local", "ChildView2026!", "Bé Minh (Chế độ minh bạch)"),
    "admin": ("admin@ogk.local", "AdminOGK2026!", "Quản trị viên OGK"),
}


def load_domain_categories(db) -> int:
    dataset_path = DATA_DIR / "domain_categories.json"
    data = json.loads(dataset_path.read_text(encoding="utf-8"))

    emergency_set = set(data.get("emergency_whitelist_nt6", []))
    doh_endpoints = set(data.get("doh_endpoints", []))
    doh_canaries = set(data.get("doh_canary_domains", []))

    existing = {row[0] for row in db.query(DomainCategory.domain).all()}
    inserted = 0

    for category, domains in data.get("categories", {}).items():
        for dom in domains:
            d = dom.strip().lower()
            if d in existing:
                continue
            db.add(
                DomainCategory(
                    domain=d,
                    category=category,
                    is_doh_endpoint=d in doh_endpoints,
                    is_doh_canary=d in doh_canaries,
                    is_emergency_whitelist=d in emergency_set,
                )
            )
            existing.add(d)
            inserted += 1

    # Ensure DoH endpoints, DoH canaries, and NT6 emergency domains are also indexed
    for d in sorted(doh_endpoints | doh_canaries | emergency_set):
        d = d.strip().lower()
        if d in existing:
            continue
        cat = "education" if d in emergency_set else "uncategorized"
        db.add(
            DomainCategory(
                domain=d,
                category=cat,
                is_doh_endpoint=d in doh_endpoints,
                is_doh_canary=d in doh_canaries,
                is_emergency_whitelist=d in emergency_set,
            )
        )
        existing.add(d)
        inserted += 1

    db.commit()
    return inserted


def create_default_policy_for_child(db, child: Child, actor_user: User) -> Policy:
    existing = db.query(Policy).filter(Policy.child_id == child.id).first()
    if existing is not None:
        return existing

    tpl_path = DATA_DIR / "default_policy_6_11.json"
    tpl = json.loads(tpl_path.read_text(encoding="utf-8"))
    tpl.pop("profile_name", None)
    tpl["child_id"] = child.id
    tpl["version"] = 1

    policy_obj = PolicyConfigPayload.model_validate(tpl)
    canonical_json = json.dumps(
        policy_obj.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    sig = sign_policy_payload(policy_obj, settings.policy_hmac_master_key)
    policy = Policy(
        child_id=child.id,
        version=1,
        config_json=canonical_json,
        signature=sig,
        updated_by_user_id=actor_user.id,
        updated_at=utcnow(),
    )
    db.add(policy)
    db.add(
        AuditLog(
            child_id=child.id,
            actor_user_id=actor_user.id,
            actor_label=actor_user.email,
            action="POLICY_INITIALIZED",
            ip_address="127.0.0.1",
            new_value_json=json.dumps(
                {"version": 1, "profile": "Default Safe Companion Policy (Age 6-11)"},
                ensure_ascii=False,
            ),
        )
    )
    db.commit()
    db.refresh(policy)
    return policy


def seed_all() -> None:
    init_db()
    db = SessionLocal()
    try:
        domains_added = load_domain_categories(db)
        total_domains = db.query(DomainCategory).count()

        # 1. Parent 1
        p1_email, p1_pw, p1_name = DEMO_ACCOUNTS["parent"]
        parent1 = db.query(User).filter(User.email == p1_email).first()
        if parent1 is None:
            parent1 = User(
                email=p1_email,
                full_name=p1_name,
                password_hash=hash_password(p1_pw),
                role="parent",
            )
            db.add(parent1)
            db.commit()
            db.refresh(parent1)

        # 2. Parent 2 (for multi-tenant & anti-IDOR demo)
        p2_email, p2_pw, p2_name = DEMO_ACCOUNTS["parent2"]
        parent2 = db.query(User).filter(User.email == p2_email).first()
        if parent2 is None:
            parent2 = User(
                email=p2_email,
                full_name=p2_name,
                password_hash=hash_password(p2_pw),
                role="parent",
            )
            db.add(parent2)
            db.commit()
            db.refresh(parent2)

        # 3. Admin
        adm_email, adm_pw, adm_name = DEMO_ACCOUNTS["admin"]
        if db.query(User).filter(User.email == adm_email).first() is None:
            db.add(
                User(
                    email=adm_email,
                    full_name=adm_name,
                    password_hash=hash_password(adm_pw),
                    role="admin",
                )
            )
            db.commit()

        # 4. Children
        child1 = db.query(Child).filter(Child.parent_id == parent1.id).first()
        if child1 is None:
            child1 = Child(parent_id=parent1.id, display_name="Bé Minh", age_group="6-11")
            db.add(child1)
            db.commit()
            db.refresh(child1)

        child2 = db.query(Child).filter(Child.parent_id == parent2.id).first()
        if child2 is None:
            child2 = Child(parent_id=parent2.id, display_name="Bé An", age_group="6-11")
            db.add(child2)
            db.commit()
            db.refresh(child2)

        # 5. Child-View account linked to Child 1 (NT5)
        cv_email, cv_pw, cv_name = DEMO_ACCOUNTS["child_view"]
        if db.query(User).filter(User.email == cv_email).first() is None:
            db.add(
                User(
                    email=cv_email,
                    full_name=cv_name,
                    password_hash=hash_password(cv_pw),
                    role="child-view",
                    linked_child_id=child1.id,
                )
            )
            db.commit()

        # 6. Default signed policies
        policy1 = create_default_policy_for_child(db, child1, parent1)
        create_default_policy_for_child(db, child2, parent2)

        # 7. Demo device & sample NT2 events for Child 1
        demo_dev = db.query(Device).filter(Device.id == "dev_demo_minh_pc").first()
        if demo_dev is None:
            demo_dev = Device(
                id="dev_demo_minh_pc",
                child_id=child1.id,
                device_name="DESKTOP-MINH-STUDY",
                fingerprint_hash=sha256_hex("demo-hw-fingerprint-minh-pc"),
                os_version="Windows 11 Home x64",
                hmac_secret_enc=encrypt_sensitive("demo-hmac-secret-0123456789abcdef0123456789abcdef"),
                refresh_token_hash=sha256_hex("demo-refresh-token-minh"),
                last_heartbeat_at=utcnow(),
                last_policy_version=policy1.version,
                last_quota_used_sec=2700,
                tray_visible=True,
            )
            db.add(demo_dev)
            db.commit()

        if db.query(Event).filter(Event.child_id == child1.id).count() == 0:
            now = utcnow()
            sample_events = [
                ("seed-ev-01", now - timedelta(hours=3), "app_stop", "chrome.exe", 1800),
                ("seed-ev-02", now - timedelta(hours=2), "domain_query", "khanacademy.org", 900),
                ("seed-ev-03", now - timedelta(hours=2), "domain_query", "olm.vn", 600),
                ("seed-ev-04", now - timedelta(hours=1), "blocked_domain", "tiktok.com", 0),
                ("seed-ev-05", now - timedelta(minutes=30), "app_stop", "scratch.exe", 1200),
                ("seed-ev-06", now - timedelta(days=1, hours=2), "domain_query", "vi.wikipedia.org", 1500),
                ("seed-ev-07", now - timedelta(days=1, hours=1), "blocked_app", "steam.exe", 0),
            ]
            for key, ts, ev_type, subj, dur in sample_events:
                db.add(
                    Event(
                        idempotency_key=key,
                        ts=ts,
                        device_id=demo_dev.id,
                        child_id=child1.id,
                        type=ev_type,
                        subject=subj,
                        duration_sec=dur,
                        policy_id=policy1.id,
                    )
                )
            db.add(
                ChildRequest(
                    child_id=child1.id,
                    device_id=demo_dev.id,
                    request_type="unlock_request",
                    subject="daily_quota",
                    message="Con còn 1 bài tập Scratch sắp xong, cho con xin thêm 15 phút ạ!",
                    requested_minutes=15,
                    status="pending",
                )
            )
            db.commit()

        print("=" * 68)
        print("OGK Database Seeded Successfully!")
        print(f"  Database path : {settings.db_path}")
        print(f"  Domain catalog: {total_domains} total ({domains_added} newly inserted)")
        print("  Demo Accounts :")
        for role_key, (email, pw, label) in DEMO_ACCOUNTS.items():
            print(f"    - [{role_key:10s}] {email:20s} / {pw}  ({label})")
        print("=" * 68)
    finally:
        db.close()


if __name__ == "__main__":
    seed_all()
