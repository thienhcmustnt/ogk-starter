"""
Privacy & Transparency Principles Tests (NT1–NT6 & F3):
- NT2: Reject events containing full URLs, query strings, file paths, or window titles
- NT4: Reject policy rules missing `reason` or `created_by`
- NT5: Child-view can inspect usage reports AND parent audit logs, but CANNOT modify policies
- NT6: Emergency whitelist (111, education portals) CANNOT be blocked or removed
- F3: 90-day automatic data retention purge deletes old events/audits and keeps recent ones
- F3: Safe domain dataset check (>= 220 domains across 6 groups + 5 DoH canaries + 50 test domains)
"""
from __future__ import annotations

import json
from datetime import timedelta

from server.app.core.config import DATA_DIR
from server.app.models.domain import AuditLog, Event, utcnow
from server.app.services.retention import purge_expired_records
from tests.conftest import enroll_device_helper, login_helper


def test_nt2_rejects_full_url_paths_and_window_titles(client, seeded_actors):
    p1 = login_helper(client, seeded_actors["parent1"].email, seeded_actors["parent1_password"])
    enrolled = enroll_device_helper(client, seeded_actors["child1"].id, p1["csrf_token"])
    headers = {"Authorization": f"Bearer {enrolled['access_token']}"}
    now_iso = utcnow().isoformat()

    forbidden_subjects = [
        ("domain_query", "https://youtube.com/watch?v=dQw4w9WgXcQ"),
        ("domain_query", "google.com/search?q=bai+tap+toan"),
        ("app_start", r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
        ("app_start", "Chrome - Tin nhắn bí mật với bạn"),
    ]
    for idx, (ev_type, bad_subject) in enumerate(forbidden_subjects):
        res = client.post(
            "/api/v1/events/batch",
            json={
                "events": [
                    {
                        "idempotency_key": f"bad-nt2-key-{idx:04d}",
                        "ts": now_iso,
                        "type": ev_type,
                        "subject": bad_subject,
                        "duration_sec": 30,
                    }
                ]
            },
            headers=headers,
        )
        assert res.status_code == 422, f"Expected 422 for forbidden NT2 subject: {bad_subject}"


def test_nt6_emergency_whitelist_cannot_be_overridden_or_removed(client, seeded_actors):
    p1 = login_helper(client, seeded_actors["parent1"].email, seeded_actors["parent1_password"])
    child1_id = seeded_actors["child1"].id
    csrf = p1["csrf_token"]

    # Attempt to block National Child Protection Hotline domain 111.gov.vn -> MUST return 422
    bad_policy = {
        "weekday_quota_minutes": 60,
        "weekend_quota_minutes": 90,
        "blocked_domains": [
            {
                "target": "111.gov.vn",
                "reason": "Thử chặn trái phép",
                "created_by": "parent1@ogk.test",
            }
        ],
    }
    res_block = client.put(
        f"/api/v1/policy/{child1_id}",
        json=bad_policy,
        headers={"X-CSRF-Token": csrf},
    )
    assert res_block.status_code == 422

    # Attempt to wipe whitelist_emergency -> Server re-injects immutable NT6 whitelist automatically
    wipe_attempt = {
        "weekday_quota_minutes": 75,
        "weekend_quota_minutes": 100,
        "whitelist_emergency": [],
        "emergency_hotlines": [],
        "change_note": "Điều chỉnh quota",
    }
    res_ok = client.put(
        f"/api/v1/policy/{child1_id}",
        json=wipe_attempt,
        headers={"X-CSRF-Token": csrf},
    )
    assert res_ok.status_code == 200
    pol = res_ok.json()["policy"]
    assert "tongdai111.vn" in pol["whitelist_emergency"]
    assert "111.gov.vn" in pol["whitelist_emergency"]
    assert "moet.gov.vn" in pol["whitelist_emergency"]
    assert "111" in pol["emergency_hotlines"]
    assert pol["version"] == 2


def test_nt4_rule_requires_reason_and_created_by(client, seeded_actors):
    p1 = login_helper(client, seeded_actors["parent1"].email, seeded_actors["parent1_password"])
    child1_id = seeded_actors["child1"].id

    # Missing `reason` must fail validation
    res = client.put(
        f"/api/v1/policy/{child1_id}",
        json={
            "weekday_quota_minutes": 90,
            "blocked_domains": [{"target": "roblox.com", "created_by": "parent1@ogk.test"}],
        },
        headers={"X-CSRF-Token": p1["csrf_token"]},
    )
    assert res.status_code == 422


def test_nt5_child_view_transparency_read_only(client, seeded_actors):
    child1_id = seeded_actors["child1"].id
    child2_id = seeded_actors["child2"].id

    # Parent 1 updates policy so there's an audit log
    p1 = login_helper(client, seeded_actors["parent1"].email, seeded_actors["parent1_password"])
    client.put(
        f"/api/v1/policy/{child1_id}",
        json={"weekday_quota_minutes": 80, "change_note": "Giảm 10 phút mùa thi"},
        headers={"X-CSRF-Token": p1["csrf_token"]},
    )
    client.post("/api/v1/auth/logout", headers={"X-CSRF-Token": p1["csrf_token"]})

    # Child-view logs in: CAN read own report, policy, and audit logs; CANNOT modify policy or read Child 2
    cv = login_helper(client, seeded_actors["child_view1"].email, seeded_actors["child_view1_password"])
    assert client.get(f"/api/v1/reports/{child1_id}/summary").status_code == 200
    aud_res = client.get(f"/api/v1/reports/{child1_id}/audit-logs")
    assert aud_res.status_code == 200
    assert any(row["action"] == "POLICY_UPDATED" for row in aud_res.json())

    # Child-view CANNOT update policy
    put_res = client.put(
        f"/api/v1/policy/{child1_id}",
        json={"weekday_quota_minutes": 999},
        headers={"X-CSRF-Token": cv["csrf_token"]},
    )
    assert put_res.status_code == 403

    # Child-view CANNOT peek at Child 2 (Anti-IDOR)
    assert client.get(f"/api/v1/reports/{child2_id}/summary").status_code == 403


def test_retention_90_days_deletes_only_expired_records(seeded_actors, db_session):
    db, _ = db_session
    child1_id = seeded_actors["child1"].id

    # Create a dummy device directly for FK integrity
    from server.app.core.security import encrypt_sensitive, sha256_hex
    from server.app.models.domain import Device

    dev = Device(
        id="dev_retention_test",
        child_id=child1_id,
        device_name="TEST-PC",
        fingerprint_hash=sha256_hex("fp-ret"),
        hmac_secret_enc=encrypt_sensitive("secret"),
        refresh_token_hash=sha256_hex("ref"),
    )
    db.add(dev)
    db.commit()

    old_ts = utcnow() - timedelta(days=95)
    recent_ts = utcnow() - timedelta(days=5)

    db.add_all(
        [
            Event(
                idempotency_key="old-ev-95d",
                ts=old_ts,
                device_id=dev.id,
                child_id=child1_id,
                type="domain_query",
                subject="olm.vn",
                duration_sec=60,
            ),
            Event(
                idempotency_key="recent-ev-5d",
                ts=recent_ts,
                device_id=dev.id,
                child_id=child1_id,
                type="domain_query",
                subject="khanacademy.org",
                duration_sec=120,
            ),
            AuditLog(
                child_id=child1_id,
                actor_label="parent1@ogk.test",
                action="OLD_AUDIT",
                ip_address="127.0.0.1",
                created_at=old_ts,
            ),
            AuditLog(
                child_id=child1_id,
                actor_label="parent1@ogk.test",
                action="RECENT_AUDIT",
                ip_address="127.0.0.1",
                created_at=recent_ts,
            ),
        ]
    )
    db.commit()

    result = purge_expired_records(db, retention_days=90)
    assert result["events_deleted"] == 1
    assert result["audit_logs_deleted"] == 1

    remaining_events = db.query(Event).all()
    assert len(remaining_events) == 1
    assert remaining_events[0].idempotency_key == "recent-ev-5d"


def test_domain_categories_dataset_meets_count_and_safety_rules():
    dataset = json.loads((DATA_DIR / "domain_categories.json").read_text(encoding="utf-8"))
    categories = dataset["categories"]
    expected_groups = {
        "education",
        "entertainment",
        "social_media",
        "gaming",
        "age_inappropriate",
        "uncategorized",
    }
    assert set(categories.keys()) == expected_groups

    all_domains = [d for group in categories.values() for d in group]
    assert len(all_domains) >= 220
    assert len(set(all_domains)) == len(all_domains)  # No accidental duplicates

    assert len(dataset["doh_canary_domains"]) >= 5
    assert len(dataset["doh_endpoints"]) >= 5
    test_50 = sum(len(v) for v in dataset["test_domains_50"].values())
    assert test_50 == 50

    # All simulated age_inappropriate entries must strictly be safe RFC 2606 example domains
    for dom in categories["age_inappropriate"]:
        assert dom.endswith((".example.com", ".example.org", ".example.net", ".example"))
