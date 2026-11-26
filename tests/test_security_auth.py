"""
Security & Authentication Unit/API Tests (F5):
- Argon2id password hashing & minimum 10-char enforcement
- AES-256-GCM encryption/decryption roundtrip & tamper detection
- Brute-force lockout (5 failed logins -> 423 Locked for 15 minutes)
- Server-side session logout revocation
- CSRF enforcement on mutating endpoints
- Anti-IDOR isolation between Parent 1 and Parent 2 (and child-view restrictions)
"""
from __future__ import annotations

import pytest

from server.app.core.security import (
    decrypt_sensitive,
    encrypt_sensitive,
    hash_password,
    verify_password,
)
from tests.conftest import enroll_device_helper, login_helper


def test_argon2id_password_hashing_and_min_length():
    hashed = hash_password("StrongPass2026!")
    assert hashed.startswith("$argon2id$")
    assert verify_password("StrongPass2026!", hashed) is True
    assert verify_password("WrongPass2026!", hashed) is False

    with pytest.raises(ValueError):
        hash_password("short99")


def test_aes_gcm_encryption_roundtrip_and_tamper_detection():
    secret = "super-sensitive-device-hmac-secret-12345"
    encrypted = encrypt_sensitive(secret)
    assert encrypted != secret
    assert decrypt_sensitive(encrypted) == secret

    # Flip a character in the ciphertext -> authentication tag must fail
    tampered = encrypted[:-2] + ("AA" if not encrypted.endswith("AA") else "BB")
    with pytest.raises(Exception):
        decrypt_sensitive(tampered)


def test_brute_force_lockout_after_5_failed_attempts(client, seeded_actors):
    email = seeded_actors["parent1"].email

    for attempt in range(4):
        res = client.post("/api/v1/auth/login", json={"email": email, "password": "WrongPassword99!"})
        assert res.status_code == 401, f"Attempt {attempt + 1} expected 401"

    # 5th failed attempt triggers 15-minute account lockout (423 Locked)
    res5 = client.post("/api/v1/auth/login", json={"email": email, "password": "WrongPassword99!"})
    assert res5.status_code == 423

    # Even with the right password, account remains locked
    res_good = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": seeded_actors["parent1_password"]},
    )
    assert res_good.status_code == 423


def test_logout_revokes_session_server_side_and_csrf_is_enforced(client, seeded_actors):
    login_data = login_helper(client, seeded_actors["parent1"].email, seeded_actors["parent1_password"])
    csrf = login_data["csrf_token"]
    child1_id = seeded_actors["child1"].id

    # Missing CSRF token on mutating endpoint MUST return 403
    no_csrf = client.post("/api/v1/enroll/code", json={"child_id": child1_id})
    assert no_csrf.status_code == 403

    # Wrong CSRF token MUST return 403
    bad_csrf = client.post(
        "/api/v1/enroll/code",
        json={"child_id": child1_id},
        headers={"X-CSRF-Token": "invalid-csrf-token"},
    )
    assert bad_csrf.status_code == 403

    # Valid CSRF succeeds
    ok_resp = client.post(
        "/api/v1/enroll/code",
        json={"child_id": child1_id},
        headers={"X-CSRF-Token": csrf},
    )
    assert ok_resp.status_code == 201

    # Capture session cookie, logout, then replay old cookie -> MUST be rejected (401)
    saved_session_cookie = client.cookies.get("ogk_session")
    assert saved_session_cookie

    logout_resp = client.post("/api/v1/auth/logout", headers={"X-CSRF-Token": csrf})
    assert logout_resp.status_code == 200

    client.cookies.set("ogk_session", saved_session_cookie)
    replay_resp = client.get("/api/v1/auth/me")
    assert replay_resp.status_code == 401


def test_anti_idor_between_two_parents(client, seeded_actors):
    child1_id = seeded_actors["child1"].id
    child2_id = seeded_actors["child2"].id

    # Parent 1 logs in and enrolls a device for Child 1
    p1_login = login_helper(client, seeded_actors["parent1"].email, seeded_actors["parent1_password"])
    dev1 = enroll_device_helper(client, child1_id, p1_login["csrf_token"], device_name="CHILD1-PC")
    client.post("/api/v1/auth/logout", headers={"X-CSRF-Token": p1_login["csrf_token"]})

    # Parent 2 logs in and tries to access Child 1's resources -> ALL MUST return 403!
    p2_login = login_helper(client, seeded_actors["parent2"].email, seeded_actors["parent2_password"])
    p2_csrf = p2_login["csrf_token"]

    assert client.get(f"/api/v1/policy/{child1_id}").status_code == 403
    assert client.get(f"/api/v1/reports/{child1_id}/summary").status_code == 403
    assert client.get(f"/api/v1/reports/{child1_id}/audit-logs").status_code == 403
    assert (
        client.post(
            "/api/v1/enroll/code",
            json={"child_id": child1_id},
            headers={"X-CSRF-Token": p2_csrf},
        ).status_code
        == 403
    )
    assert (
        client.post(
            f"/api/v1/commands/{dev1['device_id']}",
            json={"command": "LOCK_NOW", "payload": {}},
            headers={"X-CSRF-Token": p2_csrf},
        ).status_code
        == 403
    )
    assert (
        client.delete(
            f"/api/v1/reports/{child1_id}/purge",
            headers={"X-CSRF-Token": p2_csrf},
        ).status_code
        == 403
    )

    # Parent 2 CAN access their own Child 2
    assert client.get(f"/api/v1/policy/{child2_id}").status_code == 200
    assert client.get(f"/api/v1/reports/{child2_id}/summary").status_code == 200
