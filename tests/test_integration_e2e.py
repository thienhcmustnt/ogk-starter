"""
End-to-End Integration Scenarios (Section 8: >= 5 integration flows):
1. Full device onboarding -> HMAC policy sync -> heartbeat version drift detection -> re-sync
2. Offline telemetry batch ingestion -> Daily/Weekly Report Summary -> CSV & PDF Export
3. NT3 Child Voice workflow: Child submits `unlock_request` -> Parent approves -> `ADD_15M` command queued/pushed + `override_granted` logged
4. NT3 False Positive Report workflow: Child reports blocked education site -> Parent reviews & responds
5. F3 Right-to-Erasure workflow: Parent clicks Purge (`DELETE /reports/{child_id}/purge`) -> server events wiped + `PURGE_CACHE` delivered to agent
"""
from __future__ import annotations

from contracts.shared_schemas import PolicyConfigPayload, verify_policy_signature
from server.app.models.domain import utcnow
from tests.conftest import enroll_device_helper, login_helper


def test_e2e_1_enrollment_policy_update_and_heartbeat_sync(client, seeded_actors):
    p1 = login_helper(client, seeded_actors["parent1"].email, seeded_actors["parent1_password"])
    child1_id = seeded_actors["child1"].id
    enrolled = enroll_device_helper(client, child1_id, p1["csrf_token"], device_name="E2E-PC-1")
    dev_headers = {"Authorization": f"Bearer {enrolled['access_token']}"}

    # Initial policy fetch (v1)
    p_v1 = client.get(f"/api/v1/policy/{child1_id}", headers=dev_headers).json()
    assert p_v1["policy"]["version"] == 1
    assert verify_policy_signature(
        PolicyConfigPayload.model_validate(p_v1["policy"]),
        p_v1["signature"],
        enrolled["hmac_secret"],
    )

    # Parent updates policy -> bumps to v2
    upd = client.put(
        f"/api/v1/policy/{child1_id}",
        json={
            "weekday_quota_minutes": 45,
            "weekend_quota_minutes": 90,
            "change_note": "Tuần thi học kỳ",
        },
        headers={"X-CSRF-Token": p1["csrf_token"]},
    )
    assert upd.status_code == 200
    assert upd.json()["policy"]["version"] == 2

    # Agent sends heartbeat reporting v1 -> server flags policy_update_required=True + SYNC_POLICY command
    hb = client.post(
        "/api/v1/heartbeat",
        json={
            "device_id": enrolled["device_id"],
            "device_ts": utcnow().isoformat(),
            "policy_version": 1,
            "quota_used_seconds": 900,
        },
        headers=dev_headers,
    )
    assert hb.status_code == 200
    hb_data = hb.json()
    assert hb_data["latest_policy_version"] == 2
    assert hb_data["policy_update_required"] is True
    assert any(c["command"] == "SYNC_POLICY" for c in hb_data["pending_commands"])

    # Agent fetches v2 and verifies HMAC signature
    p_v2 = client.get(f"/api/v1/policy/{child1_id}", headers=dev_headers).json()
    assert p_v2["policy"]["version"] == 2
    assert p_v2["policy"]["weekday_quota_minutes"] == 45
    assert verify_policy_signature(
        PolicyConfigPayload.model_validate(p_v2["policy"]),
        p_v2["signature"],
        enrolled["hmac_secret"],
    )


def test_e2e_2_telemetry_to_reports_and_csv_pdf_export(client, seeded_actors):
    p1 = login_helper(client, seeded_actors["parent1"].email, seeded_actors["parent1_password"])
    child1_id = seeded_actors["child1"].id
    enrolled = enroll_device_helper(client, child1_id, p1["csrf_token"], device_name="E2E-PC-2")
    dev_headers = {"Authorization": f"Bearer {enrolled['access_token']}"}
    now_iso = utcnow().isoformat()

    batch_resp = client.post(
        "/api/v1/events/batch",
        json={
            "events": [
                {
                    "idempotency_key": "e2e-ev-0001",
                    "ts": now_iso,
                    "type": "app_stop",
                    "subject": "chrome.exe",
                    "duration_sec": 1200,
                },
                {
                    "idempotency_key": "e2e-ev-0002",
                    "ts": now_iso,
                    "type": "domain_query",
                    "subject": "olm.vn",
                    "duration_sec": 600,
                },
                {
                    "idempotency_key": "e2e-ev-0003",
                    "ts": now_iso,
                    "type": "blocked_domain",
                    "subject": "tiktok.com",
                    "duration_sec": 0,
                },
            ]
        },
        headers=dev_headers,
    )
    assert batch_resp.status_code == 200
    assert batch_resp.json()["accepted"] == 3

    summary = client.get(f"/api/v1/reports/{child1_id}/summary?days=7").json()
    assert summary["total_duration_sec"] == 1800
    assert summary["total_blocked_events"] == 1
    assert summary["top_apps"][0]["subject"] == "chrome.exe"
    assert any(d["subject"] == "olm.vn" for d in summary["top_domains"])

    csv_resp = client.get(f"/api/v1/reports/{child1_id}/export?format=csv&days=7")
    assert csv_resp.status_code == 200
    assert "text/csv" in csv_resp.headers["content-type"]
    assert "chrome.exe" in csv_resp.text

    pdf_resp = client.get(f"/api/v1/reports/{child1_id}/export?format=pdf&days=7")
    assert pdf_resp.status_code == 200
    assert pdf_resp.headers["content-type"] == "application/pdf"
    assert pdf_resp.content.startswith(b"%PDF-1.4")


def test_e2e_3_child_unlock_request_approved_dispatches_add_15m(client, seeded_actors):
    p1 = login_helper(client, seeded_actors["parent1"].email, seeded_actors["parent1_password"])
    child1_id = seeded_actors["child1"].id
    enrolled = enroll_device_helper(client, child1_id, p1["csrf_token"], device_name="E2E-PC-3")
    dev_headers = {"Authorization": f"Bearer {enrolled['access_token']}"}

    # Child submits unlock request from Tray UI via Agent
    req_resp = client.post(
        "/api/v1/requests",
        json={
            "request_type": "unlock_request",
            "subject": "daily_quota",
            "message": "Con đang làm nốt bài tiếng Anh trên IOE, xin thêm 15 phút ạ!",
            "requested_minutes": 15,
        },
        headers=dev_headers,
    )
    assert req_resp.status_code == 201
    req_id = req_resp.json()["id"]
    assert req_resp.json()["status"] == "pending"

    # Parent approves with 15 minutes
    dec_resp = client.post(
        f"/api/v1/requests/{req_id}/decision",
        json={
            "decision": "approved",
            "response_message": "Đồng ý, con làm xong bài rồi nghỉ mắt nhé!",
            "grant_minutes": 15,
        },
        headers={"X-CSRF-Token": p1["csrf_token"]},
    )
    assert dec_resp.status_code == 200
    assert dec_resp.json()["status"] == "approved"

    # Agent receives ADD_15M on next heartbeat (or WS)
    hb = client.post(
        "/api/v1/heartbeat",
        json={
            "device_id": enrolled["device_id"],
            "device_ts": utcnow().isoformat(),
            "policy_version": 1,
        },
        headers=dev_headers,
    )
    assert hb.status_code == 200
    cmds = hb.json()["pending_commands"]
    assert any(c["command"] == "ADD_15M" and c["payload"]["minutes"] == 15 for c in cmds)


def test_e2e_4_child_view_false_positive_report_and_parent_response(client, seeded_actors):
    child1_id = seeded_actors["child1"].id

    # Child logs into child-view web UI and submits false-positive report
    cv = login_helper(client, seeded_actors["child_view1"].email, seeded_actors["child_view1_password"])
    rep = client.post(
        "/api/v1/requests",
        json={
            "request_type": "false_positive_report",
            "subject": "scratch.mit.edu",
            "message": "Em nghĩ trang lập trình này bị chặn nhầm ạ.",
        },
        headers={"X-CSRF-Token": cv["csrf_token"]},
    )
    assert rep.status_code == 201
    req_id = rep.json()["id"]
    client.post("/api/v1/auth/logout", headers={"X-CSRF-Token": cv["csrf_token"]})

    # Parent reviews and replies
    p1 = login_helper(client, seeded_actors["parent1"].email, seeded_actors["parent1_password"])
    dec = client.post(
        f"/api/v1/requests/{req_id}/decision",
        json={
            "decision": "approved",
            "response_message": "Ba đã kiểm tra và mở lại scratch.mit.edu cho con.",
        },
        headers={"X-CSRF-Token": p1["csrf_token"]},
    )
    assert dec.status_code == 200
    assert dec.json()["parent_response"].startswith("Ba đã kiểm tra")

    # Request list reflects the resolved decision
    all_reqs = client.get(f"/api/v1/requests/{child1_id}").json()
    assert len(all_reqs) == 1
    assert all_reqs[0]["status"] == "approved"


def test_e2e_5_right_to_erasure_purge_clears_server_and_notifies_agent(client, seeded_actors):
    p1 = login_helper(client, seeded_actors["parent1"].email, seeded_actors["parent1_password"])
    child1_id = seeded_actors["child1"].id
    enrolled = enroll_device_helper(client, child1_id, p1["csrf_token"], device_name="E2E-PC-5")
    dev_headers = {"Authorization": f"Bearer {enrolled['access_token']}"}

    # Ingest events
    client.post(
        "/api/v1/events/batch",
        json={
            "events": [
                {
                    "idempotency_key": "purge-ev-0001",
                    "ts": utcnow().isoformat(),
                    "type": "domain_query",
                    "subject": "vi.wikipedia.org",
                    "duration_sec": 450,
                }
            ]
        },
        headers=dev_headers,
    )

    # Connect agent WS to verify immediate PURGE_CACHE push
    ws_url = f"/ws/device/{enrolled['device_id']}?token={enrolled['access_token']}"
    with client.websocket_connect(ws_url) as ws:
        purge_resp = client.delete(
            f"/api/v1/reports/{child1_id}/purge",
            headers={"X-CSRF-Token": p1["csrf_token"]},
        )
        assert purge_resp.status_code == 200
        pdata = purge_resp.json()
        assert pdata["events_deleted"] == 1
        assert pdata["devices_notified"] == 1

        ws_msg = ws.receive_json()
        assert ws_msg["command"] == "PURGE_CACHE"

    # Server report now shows 0 duration
    summary_after = client.get(f"/api/v1/reports/{child1_id}/summary?days=7").json()
    assert summary_after["total_duration_sec"] == 0
    assert summary_after["top_domains"] == []
