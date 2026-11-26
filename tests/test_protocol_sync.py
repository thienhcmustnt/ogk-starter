"""
Protocol, Sync, Cryptography & Real-time Command Tests (Section 4.3, F4, M6):
- 8-character pairing code (single-use, 10-minute expiry)
- HMAC-SHA256 policy signing & tamper detection via shared `verify_policy_signature()`
- Heartbeat clock-skew detection (> 120s) + AuditLog alert
- Batch event deduplication via `idempotency_key`
- Device refresh token & device revocation
- Real-time WebSocket command push (< 5s latency)
"""
from __future__ import annotations

from datetime import timedelta

from contracts.shared_schemas import PolicyConfigPayload, verify_policy_signature
from server.app.models.domain import AuditLog, PairingCode, utcnow
from tests.conftest import enroll_device_helper, login_helper


def test_pairing_code_format_single_use_and_expiry(client, seeded_actors, db_session):
    db, _ = db_session
    p1 = login_helper(client, seeded_actors["parent1"].email, seeded_actors["parent1_password"])
    child1_id = seeded_actors["child1"].id

    res = client.post(
        "/api/v1/enroll/code",
        json={"child_id": child1_id},
        headers={"X-CSRF-Token": p1["csrf_token"]},
    )
    assert res.status_code == 201
    code = res.json()["code"]
    assert len(code) == 8
    assert code.isalnum() and code.isupper()

    # Enroll once succeeds
    enroll1 = client.post(
        "/api/v1/enroll/device",
        json={
            "code": code,
            "device_name": "KID-LAPTOP-1",
            "device_fingerprint": "hw-fp-1111111111",
        },
    )
    assert enroll1.status_code == 201
    data = enroll1.json()
    assert data["device_id"].startswith("dev_")
    assert len(data["hmac_secret"]) == 64

    # Re-using the same code MUST fail
    enroll2 = client.post(
        "/api/v1/enroll/device",
        json={
            "code": code,
            "device_name": "KID-LAPTOP-2",
            "device_fingerprint": "hw-fp-2222222222",
        },
    )
    assert enroll2.status_code == 400

    # Expired code MUST fail
    expired_code = PairingCode(
        code="EXPD1234",
        child_id=child1_id,
        created_by_user_id=seeded_actors["parent1"].id,
        expires_at=utcnow() - timedelta(minutes=1),
    )
    db.add(expired_code)
    db.commit()

    enroll_expired = client.post(
        "/api/v1/enroll/device",
        json={
            "code": "EXPD1234",
            "device_name": "KID-LAPTOP-3",
            "device_fingerprint": "hw-fp-3333333333",
        },
    )
    assert enroll_expired.status_code == 400


def test_hmac_policy_signature_verification_and_tamper_rejection(client, seeded_actors):
    p1 = login_helper(client, seeded_actors["parent1"].email, seeded_actors["parent1_password"])
    child1_id = seeded_actors["child1"].id
    enrolled = enroll_device_helper(client, child1_id, p1["csrf_token"])

    # Device fetches policy with its Bearer access token
    pol_resp = client.get(
        f"/api/v1/policy/{child1_id}",
        headers={"Authorization": f"Bearer {enrolled['access_token']}"},
    )
    assert pol_resp.status_code == 200
    envelope = pol_resp.json()
    policy_obj = PolicyConfigPayload.model_validate(envelope["policy"])

    # Valid signature passes verification with the device's enrolled hmac_secret
    assert verify_policy_signature(policy_obj, envelope["signature"], enrolled["hmac_secret"]) is True

    # Tampering quota from 90 -> 900 invalidates signature!
    tampered_dict = policy_obj.model_dump(mode="json")
    tampered_dict["weekday_quota_minutes"] = 900
    assert verify_policy_signature(tampered_dict, envelope["signature"], enrolled["hmac_secret"]) is False

    # Wrong secret also fails
    assert verify_policy_signature(policy_obj, envelope["signature"], "wrong-secret") is False


def test_heartbeat_clock_skew_detection_logs_audit_alert(client, seeded_actors, db_session):
    db, _ = db_session
    p1 = login_helper(client, seeded_actors["parent1"].email, seeded_actors["parent1_password"])
    child1_id = seeded_actors["child1"].id
    enrolled = enroll_device_helper(client, child1_id, p1["csrf_token"])
    headers = {"Authorization": f"Bearer {enrolled['access_token']}"}

    # Normal heartbeat within 5 seconds -> clock_skew_detected is False
    ok_hb = client.post(
        "/api/v1/heartbeat",
        json={
            "device_id": enrolled["device_id"],
            "device_ts": utcnow().isoformat(),
            "policy_version": 1,
            "quota_used_seconds": 600,
            "tray_visible": True,
        },
        headers=headers,
    )
    assert ok_hb.status_code == 200
    assert ok_hb.json()["clock_skew_detected"] is False

    # Child rolls system clock back by 3 hours -> clock_skew_detected is True + AuditLog written
    tampered_ts = (utcnow() - timedelta(hours=3)).isoformat()
    skew_hb = client.post(
        "/api/v1/heartbeat",
        json={
            "device_id": enrolled["device_id"],
            "device_ts": tampered_ts,
            "policy_version": 1,
            "quota_used_seconds": 600,
            "tray_visible": True,
        },
        headers=headers,
    )
    assert skew_hb.status_code == 200
    skew_data = skew_hb.json()
    assert skew_data["clock_skew_detected"] is True
    assert skew_data["skew_seconds"] >= 10700

    audit_row = (
        db.query(AuditLog)
        .filter(AuditLog.child_id == child1_id, AuditLog.action == "CLOCK_SKEW_DETECTED")
        .first()
    )
    assert audit_row is not None


def test_events_batch_idempotency_prevents_double_counting(client, seeded_actors):
    p1 = login_helper(client, seeded_actors["parent1"].email, seeded_actors["parent1_password"])
    child1_id = seeded_actors["child1"].id
    enrolled = enroll_device_helper(client, child1_id, p1["csrf_token"])
    headers = {"Authorization": f"Bearer {enrolled['access_token']}"}

    now_iso = utcnow().isoformat()
    batch = {
        "events": [
            {
                "idempotency_key": "idem-key-000001",
                "ts": now_iso,
                "type": "app_stop",
                "subject": "chrome.exe",
                "duration_sec": 300,
            },
            {
                "idempotency_key": "idem-key-000002",
                "ts": now_iso,
                "type": "domain_query",
                "subject": "khanacademy.org",
                "duration_sec": 120,
            },
            # Duplicate inside the exact same batch
            {
                "idempotency_key": "idem-key-000001",
                "ts": now_iso,
                "type": "app_stop",
                "subject": "chrome.exe",
                "duration_sec": 300,
            },
        ]
    }
    res1 = client.post("/api/v1/events/batch", json=batch, headers=headers)
    assert res1.status_code == 200
    assert res1.json() == {"accepted": 2, "duplicates_skipped": 1}

    # Re-sending the same offline batch after reconnect skips all duplicates
    res2 = client.post("/api/v1/events/batch", json=batch, headers=headers)
    assert res2.status_code == 200
    assert res2.json() == {"accepted": 0, "duplicates_skipped": 3}


def test_device_refresh_and_revocation(client, seeded_actors):
    p1 = login_helper(client, seeded_actors["parent1"].email, seeded_actors["parent1_password"])
    child1_id = seeded_actors["child1"].id
    enrolled = enroll_device_helper(client, child1_id, p1["csrf_token"])

    # Refresh token works while active
    ref_ok = client.post(
        "/api/v1/enroll/refresh",
        json={"device_id": enrolled["device_id"], "refresh_token": enrolled["refresh_token"]},
    )
    assert ref_ok.status_code == 200
    new_access = ref_ok.json()["access_token"]
    assert new_access

    # Parent revokes device
    rev_resp = client.delete(
        f"/api/v1/enroll/devices/{enrolled['device_id']}",
        headers={"X-CSRF-Token": p1["csrf_token"]},
    )
    assert rev_resp.status_code == 200

    # Both existing access token and refresh token are now rejected
    hb_revoked = client.post(
        "/api/v1/heartbeat",
        json={
            "device_id": enrolled["device_id"],
            "device_ts": utcnow().isoformat(),
            "policy_version": 1,
        },
        headers={"Authorization": f"Bearer {new_access}"},
    )
    assert hb_revoked.status_code == 401

    ref_revoked = client.post(
        "/api/v1/enroll/refresh",
        json={"device_id": enrolled["device_id"], "refresh_token": enrolled["refresh_token"]},
    )
    assert ref_revoked.status_code == 401


def test_websocket_real_time_emergency_command(client, seeded_actors):
    p1 = login_helper(client, seeded_actors["parent1"].email, seeded_actors["parent1_password"])
    child1_id = seeded_actors["child1"].id
    enrolled = enroll_device_helper(client, child1_id, p1["csrf_token"])

    ws_url = f"/ws/device/{enrolled['device_id']}?token={enrolled['access_token']}"
    with client.websocket_connect(ws_url) as ws:
        cmd_resp = client.post(
            f"/api/v1/commands/{enrolled['device_id']}",
            json={"command": "LOCK_NOW", "payload": {"reason": "Đến giờ đi ngủ"}},
            headers={"X-CSRF-Token": p1["csrf_token"]},
        )
        assert cmd_resp.status_code == 200
        assert cmd_resp.json()["delivered_via_ws"] is True

        msg = ws.receive_json()
        assert msg["type"] == "COMMAND"
        assert msg["command"] == "LOCK_NOW"
        assert msg["payload"]["reason"] == "Đến giờ đi ngủ"

        ws.send_json({"type": "ACK", "command_id": msg["command_id"], "status": "executed"})
