# OGK — Công cụ đồng hành hỗ trợ quản lý sử dụng máy tính của trẻ em

> **Triết lý thiết kế bắt buộc:** *"Công cụ đồng hành, không phải phần mềm theo dõi lén"* — tuân thủ tuyệt đối 6 nguyên tắc minh bạch **NT1–NT6** và Nghị định 13/2023/NĐ-CP về bảo vệ dữ liệu cá nhân của trẻ em.

---

## 1. Cấu trúc Monorepo & Phân công 3 Thành viên

```text
ogk-project/
├── contracts/               # [Chung] API Contract, IPC Contract & Shared Pydantic Schemas (HMAC-SHA256, NT2, NT6)
├── data/                    # [Chung] 220+ tên miền an toàn (6 nhóm + DoH + 50 test domains) & Policy mặc định 6-11 tuổi
├── server/                  # [Thành viên 1 — Leader] FastAPI Backend, SQLite WAL, Auth/Security, WebSocket, Reports
├── agent/
│   ├── service/             # [Thành viên 2 — Bạn A] Windows Service, DNS Proxy 127.0.0.1:53, App SHA-256, TimeTracker, LocalStore
│   └── tray_ui/             # [Thành viên 3 — Bạn B] Tray UI Windows minh bạch (popup NT4, Xin thêm giờ NT3)
├── dashboard/               # [Thành viên 3 — Bạn B] Web Dashboard Phụ huynh & Màn hình minh bạch cho trẻ (Jinja2 + HTMX)
├── docs/                    # PRIVACY.md, THREATMODEL.md, và các báo cáo nhóm
└── tests/                   # Bộ kiểm thử tự động pytest (Unit Tests + Integration Tests)
```

---

## 2. Cài đặt & Chạy Server trên máy sạch (< 15 phút)

### Yêu cầu môi trường
- Python **3.11+** (tương thích cả 3.10–3.13) trên Windows 10/11 (x64)

### Bước 1: Tạo môi trường ảo và cài thư viện Server
```powershell
cd ogk-project
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r server/requirements.txt
```

### Bước 2: Khởi tạo cơ sở dữ liệu mẫu (`seed.py`)
```powershell
python server/seed.py
```
Lệnh này sẽ tạo cơ sở dữ liệu SQLite ở chế độ `WAL` (`server/ogk.db`), nạp 220+ tên miền an toàn từ `data/domain_categories.json`, khởi tạo Policy mặc định (đã ký HMAC-SHA256) và tạo các tài khoản demo:

| Vai trò | Email | Mật khẩu | Ghi chú |
|---|---|---|---|
| `parent` | `parent@ogk.local` | `ParentPass2026!` | Phụ huynh của Bé Minh |
| `parent` | `parent2@ogk.local` | `ParentTwoPass2026!` | Phụ huynh 2 (dùng kiểm thử chống IDOR) |
| `child-view` | `child@ogk.local` | `ChildView2026!` | Chế độ minh bạch hai chiều của Bé Minh (NT5) |
| `admin` | `admin@ogk.local` | `AdminOGK2026!` | Quản trị hệ thống |

### Bước 3: Chạy máy chủ OGK Server
```powershell
uvicorn server.app.main:app --host 0.0.0.0 --port 8000 --reload
```
- Dashboard khởi động: `http://127.0.0.1:8000/`
- Màn hình minh bạch cho trẻ: `http://127.0.0.1:8000/child-view`
- Tài liệu OpenAPI (Swagger UI) gửi cho Bạn A và Bạn B: `http://127.0.0.1:8000/docs`

### Chạy với TLS 1.2+ trong môi trường Lab (tự ký chứng chỉ)
```powershell
# Tạo self-signed cert (yêu cầu OpenSSL):
openssl req -x509 -newkey rsa:2048 -keyout server/key.pem -out server/cert.pem -days 365 -nodes -subj "/CN=ogk-lab.local"
$env:OGK_COOKIE_SECURE = "true"
uvicorn server.app.main:app --host 0.0.0.0 --port 8443 --ssl-keyfile server/key.pem --ssl-certfile server/cert.pem
```

---

## 3. Chạy Bộ Kiểm thử Tự động (`pytest`)

```powershell
pytest tests/ -v
```
Bộ kiểm thử bao phủ đầy đủ:
- `tests/test_security_auth.py`: Argon2id, khóa tài khoản 15 phút sau 5 lần sai, hủy phiên server-side, chống CSRF, chống IDOR giữa 2 phụ huynh khác nhau, AES-GCM encryption.
- `tests/test_protocol_sync.py`: Mã ghép đôi 8 ký tự (hạn 10 phút, dùng 1 lần), ký & kiểm chứng Policy HMAC-SHA256, phát hiện chỉnh đồng hồ `> 120s` ở Heartbeat, chống trùng `idempotency_key` ở Batch Events, đẩy lệnh khẩn qua WebSocket `< 5s`.
- `tests/test_privacy_nt.py`: Từ chối Event chứa URL đầy đủ (NT2), kiểm tra 220+ domain an toàn & không có nội dung người lớn, bảo vệ danh sách khẩn cấp NT6 không thể bị chặn/ghi đè, tự động xóa dữ liệu > 90 ngày, quyền xóa toàn bộ dữ liệu (`DELETE /purge`), minh bạch hai chiều `child-view` (NT5), luồng yêu cầu của trẻ (NT3).
- `tests/test_integration_e2e.py`: 5+ kịch bản tích hợp đầu-cuối (Enrollment → Policy Sync → Heartbeat → Events → Reports/Export/Purge & Child Request → Parent Approval → WS Command).
