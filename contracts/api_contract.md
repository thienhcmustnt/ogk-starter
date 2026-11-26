# OGK API, WebSocket & Local IPC Contract

Tài liệu đặc tả giao tiếp chuẩn giữa 3 phân hệ:
- **Server (`/server`)**: Phụ trách bởi Thành viên 1 (Leader)
- **Windows Agent Service (`/agent/service`)**: Phụ trách bởi Thành viên 2 (Bạn A)
- **Web Dashboard & Windows Tray UI (`/dashboard`, `/agent/tray_ui`)**: Phụ trách bởi Thành viên 3 (Bạn B)

Mọi Pydantic schema dùng chung nằm trong [`contracts/shared_schemas.py`](./shared_schemas.py).

---

## 1. Xác thực & Phân quyền (Auth & RBAC)

Hệ thống hỗ trợ 3 vai trò (`role`): `parent`, `child-view`, `admin`.
Mọi endpoint chứa `child_id` hoặc `device_id` đều kiểm tra quyền sở hữu tại tầng truy vấn (Anti-IDOR):
- `parent`: chỉ truy cập được `child` có `child.parent_id == current_user.id`.
- `child-view`: chỉ truy cập được `child` có `child.id == current_user.linked_child_id` (chỉ đọc báo cáo, audit log và gửi yêu cầu theo NT3/NT5).
- `admin`: truy cập quản trị hệ thống.

### 1.1. Đăng nhập Web (`POST /api/v1/auth/login`)
- **Bảo mật:** Argon2id; khóa tạm **15 phút** sau **5 lần** nhập sai; giới hạn tần suất theo IP.
- **Request JSON:**
  ```json
  { "email": "parent@ogk.local", "password": "ParentPassword123!" }
  ```
- **Response (`200 OK`):**
  - Đặt cookie `ogk_session` (`HttpOnly`, `Secure` khi bật TLS, `SameSite=Lax`, hạn 12 giờ).
  - Đặt cookie `ogk_csrf` để client đọc và gửi kèm header `X-CSRF-Token` trong mọi request ghi (`POST`, `PUT`, `PATCH`, `DELETE`).
  - Body trả về: `{ "user": {...}, "csrf_token": "..." }`.

### 1.2. Đăng xuất (`POST /api/v1/auth/logout`)
- **Headers:** `X-CSRF-Token: <csrf_token>`
- Hủy phiên trong bảng `sessions` trên server (server-side revocation) và xóa cookie.

### 1.3. Thông tin phiên hiện tại (`GET /api/v1/auth/me`)
- Trả về thông tin user, danh sách `children` được phép truy cập và `csrf_token`.

---

## 2. Ghép đôi thiết bị (Enrollment — Nghị định 13/2023)

### 2.1. Phụ huynh tạo mã ghép đôi (`POST /api/v1/enroll/code`)
- **Quyền:** `parent` (kèm `X-CSRF-Token`)
- **Request:** `{ "child_id": 1 }`
- **Response (`201 Created`):**
  ```json
  {
    "code": "A7K9P2QX",
    "child_id": 1,
    "expires_at": "2026-11-26T08:20:00Z"
  }
  ```
  Mã gồm **8 ký tự** (chữ in hoa + số dễ đọc), có hiệu lực **10 phút**, chỉ dùng 1 lần.

### 2.2. Agent ghép đôi thiết bị (`POST /api/v1/enroll/device`)
- **Request:**
  ```json
  {
    "code": "A7K9P2QX",
    "device_name": "DESKTOP-KID-01",
    "device_fingerprint": "sha256-hardware-fingerprint-string",
    "os_version": "Windows 11 Pro 23H2"
  }
  ```
- **Response (`201 Created`):**
  ```json
  {
    "device_id": "dev_9f8a7b6c5d4e",
    "child_id": 1,
    "access_token": "<JWT 15 phút>",
    "refresh_token": "<opaque token 30 ngày>",
    "hmac_secret": "<hex secret dùng verify Policy>",
    "policy_version": 1
  }
  ```

### 2.3. Làm mới token thiết bị (`POST /api/v1/enroll/refresh`)
- **Request:** `{ "device_id": "dev_...", "refresh_token": "..." }`
- **Response (`200 OK`):** Cấp `access_token` mới (15 phút). Từ chối `401` nếu thiết bị đã bị thu hồi.

### 2.4. Thu hồi thiết bị (`DELETE /api/v1/enroll/devices/{device_id}`)
- **Quyền:** `parent` (Anti-IDOR + `X-CSRF-Token`)
- Đánh dấu thiết bị bị thu hồi, đưa token vào danh sách `revoked_tokens`, ghi `audit_logs`.

---

## 3. Đồng bộ Policy (HMAC-SHA256 & NT4/NT6)

### 3.1. Lấy chính sách đã ký (`GET /api/v1/policy/{child_id}`)
- **Quyền:** Device Bearer Token (thuộc `child_id` đó) HOẶC `parent` / `child-view` (Anti-IDOR).
- **Response (`200 OK`):** `SignedPolicyEnvelope` gồm `policy`, `updated_at`, `signature_alg: "HMAC-SHA256"`, `signature`.
- **Agent BẮT BUỘC** gọi `verify_policy_signature(envelope.policy, envelope.signature, hmac_secret)` trước khi áp dụng. Nếu sai chữ ký, từ chối và giữ nguyên chính sách cũ.

### 3.2. Cập nhật chính sách (`PUT /api/v1/policy/{child_id}`)
- **Quyền:** `parent` (Anti-IDOR + `X-CSRF-Token`).
- Tự động tăng `version += 1`, kiểm tra ràng buộc **NT4** (mọi luật phải có `reason`, `created_by`) và **NT6** (không thể chặn miền khẩn cấp `111`, giáo dục).
- Ký lại bằng `HMAC-SHA256` và ghi `audit_logs` (ai, khi nào, IP, giá trị cũ và mới).

---

## 4. Nhịp tim & Chống chỉnh đồng hồ (`POST /api/v1/heartbeat`)

- **Tần suất:** Agent gọi mỗi **60 giây**.
- **Auth:** `Authorization: Bearer <device_access_token>`
- **Request:**
  ```json
  {
    "device_id": "dev_...",
    "device_ts": "2026-11-26T08:15:00Z",
    "policy_version": 1,
    "quota_used_seconds": 1800,
    "agent_status": "active",
    "tray_visible": true
  }
  ```
- **Chống chỉnh đồng hồ (M6):** Nếu `abs(server_ts - device_ts) > 120` giây:
  - Server ghi cảnh báo `CLOCK_SKEW_DETECTED` vào `audit_logs`.
  - Trả về `clock_skew_detected: true`, `skew_seconds`, và `server_ts` chuẩn.
- **Response (`200 OK`):**
  ```json
  {
    "server_ts": "2026-11-26T08:15:01Z",
    "clock_skew_detected": false,
    "skew_seconds": 1,
    "latest_policy_version": 2,
    "policy_update_required": true,
    "pending_commands": [
      { "command_id": 12, "command": "ADD_15M", "payload": {"minutes": 15}, "created_at": "..." }
    ]
  }
  ```

---

## 5. Lệnh khẩn thời gian thực (< 5 giây)

### 5.1. WebSocket kết nối từ Agent (`WS /ws/device/{device_id}?token=<device_access_token>`)
- Server giữ map các kết nối active theo `device_id`.
- Khi phụ huynh gửi lệnh, Server đẩy JSON ngay lập tức qua WebSocket:
  ```json
  {
    "type": "COMMAND",
    "command_id": 42,
    "command": "LOCK_NOW",
    "payload": { "reason": "Đến giờ ăn tối" },
    "issued_by": "parent@ogk.local",
    "issued_at": "2026-11-26T11:30:00Z"
  }
  ```
- Agent gửi lại ACK: `{ "type": "ACK", "command_id": 42, "status": "executed" }`.
- Nếu thiết bị đang mất kết nối WebSocket, lệnh được lưu hàng đợi và giao trong lần `POST /heartbeat` kế tiếp.

### 5.2. Phụ huynh phát lệnh khẩn (`POST /api/v1/commands/{device_id}`)
- **Quyền:** `parent` (Anti-IDOR + `X-CSRF-Token`).
- **Lệnh hỗ trợ:** `LOCK_NOW`, `UNLOCK_NOW`, `ADD_15M`, `PURGE_CACHE`, `PAUSE_2H`, `SYNC_POLICY`.
- **Response (`200 OK`):** `{ "command_id": 42, "delivered_via_ws": true, "command": "LOCK_NOW" }`.

---

## 6. Ghi nhận sự kiện theo lô (`POST /api/v1/events/batch`)

- **Auth:** `Authorization: Bearer <device_access_token>`
- **Tuân thủ NT2:** Từ chối `422 Unprocessable Entity` nếu `subject` chứa URL đầy đủ (`http://`, `/`, `?`, `=`, khoảng trắng, đường dẫn file).
- **Chống trùng (Idempotency):** Các sự kiện trùng `idempotency_key` sẽ bị bỏ qua an toàn (`duplicates_skipped`).
- **Request:** `{ "events": [ TelemetryEventItem, ... ] }`
- **Response (`200 OK`):** `{ "accepted": 15, "duplicates_skipped": 2 }`

---

## 7. Báo cáo, Minh bạch & Xóa dữ liệu (NT2, NT5, F3)

- `GET /api/v1/reports/{child_id}/summary?days=7` — Tổng hợp thời lượng ngày/tuần, Top 10 app, Top 10 domain, số lần bị chặn. Truy cập được bởi cả `parent` và `child-view` (NT5).
- `GET /api/v1/reports/{child_id}/audit-logs` — Nhật ký thay đổi chính sách của phụ huynh (ai, lúc nào, IP, giá trị cũ/mới). Truy cập được bởi cả `parent` và `child-view` (NT5).
- `GET /api/v1/reports/{child_id}/export?format=csv|pdf` — Xuất báo cáo tuần ra CSV hoặc PDF.
- `DELETE /api/v1/reports/{child_id}/purge` — Quyền `parent` (+ CSRF). Xóa toàn bộ `events` và `child_requests` của trẻ trên Server, đồng thời gửi lệnh `PURGE_CACHE` tới tất cả thiết bị của trẻ.

---

## 8. Yêu cầu từ trẻ (NT3 — Trẻ có tiếng nói)

- `POST /api/v1/requests` — Gửi yêu cầu `unlock_request` (Xin thêm giờ) hoặc `false_positive_report` (Báo trang bị chặn nhầm). Chấp nhận `child-view` session hoặc `device_access_token`.
- `GET /api/v1/requests/{child_id}` — Xem danh sách yêu cầu và trạng thái phản hồi (cả `parent` và `child-view`).
- `POST /api/v1/requests/{request_id}/decision` — Phụ huynh duyệt (`approved`) hoặc từ chối (`rejected`) kèm `response_message`. Nếu duyệt `unlock_request`, server tự động phát lệnh `ADD_15M` (hoặc số phút phụ huynh chọn) xuống thiết bị và ghi event `override_granted`.

---

## 9. Giao thức IPC cục bộ giữa Windows Service và Tray UI (Cho Bạn A & Bạn B)

Windows Service chạy dưới quyền `LocalSystem`; Tray UI chạy trong phiên người dùng của trẻ. Hai tiến trình giao tiếp cục bộ qua **Local HTTP trên `127.0.0.1:47891`** (hoặc Windows Named Pipe `\\.\pipe\ogk_agent_ipc`) với token cục bộ đọc từ `C:\ProgramData\OGK\ipc_token.txt` (quyền Read cho Users, Write chỉ cho SYSTEM/Administrators).

| Endpoint IPC cục bộ | Hướng | Mô tả |
|---|---|---|
| `GET http://127.0.0.1:47891/ipc/status` | Tray UI -> Service | Lấy `LocalIPCStatusResponse`: thời gian còn lại, trạng thái khóa, policy_version, trạng thái online/offline. |
| `GET http://127.0.0.1:47891/ipc/notifications` | Tray UI -> Service | Poll hoặc SSE nhận `LocalIPCBlockNotice` (lý do chặn NT4 + cảnh báo 10/5/1 phút). |
| `POST http://127.0.0.1:47891/ipc/tray-heartbeat` | Tray UI -> Service | Tray UI báo còn hiển thị icon mỗi 10s. Nếu quá 30s không có Tray UI (NT1 chống stealth), Service ghi log và tạm dừng thực thi ngầm. |
| `POST http://127.0.0.1:47891/ipc/request` | Tray UI -> Service | Chuyển tiếp yêu cầu "Xin thêm giờ" hoặc "Báo chặn nhầm" từ trẻ qua Service gửi về Server (có đệm offline nếu mất mạng). |
| `GET http://127.0.0.1:47891/ipc/today-summary` | Tray UI -> Service | Trả về thống kê hôm nay cục bộ cho màn hình *"Hôm nay em đã dùng gì"*. |
