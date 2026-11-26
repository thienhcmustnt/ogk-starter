# GIỚI THIỆU ĐỒ ÁN OGK & TỔNG HỢP NHỮNG GÌ ĐÃ LÀM

> **Đồ án môn Mạng máy tính (Nhóm 03 sinh viên — 06 tuần)**
> **Đề tài:** *OGK — Xây dựng ứng dụng hỗ trợ quản lý việc sử dụng máy tính của trẻ em ("Công cụ đồng hành, không phải phần mềm theo dõi lén")*

---

## 1. Giới thiệu đồ án & 6 Nguyên tắc Minh bạch bắt buộc (NT1–NT6)

**OGK** là hệ thống client–server phân tán giúp cha mẹ và con cái (độ tuổi 6–11) cùng thống nhất giờ học/giờ chơi và lọc nội dung web/ứng dụng trên Windows 10/11 (x64) một cách **minh bạch hai chiều**.

Mọi quyết định thiết kế mã nguồn và cơ sở dữ liệu đều khóa cứng theo 6 nguyên tắc bắt buộc:
1. **NT1 (Nhận biết):** Không có chế độ ẩn (stealth). Icon khay hệ thống (Tray UI) bắt buộc luôn hiển thị; nếu Tray UI mất kết nối > 30s, Service ghi cảnh báo kiểm toán và dừng thực thi ngầm.
2. **NT2 (Tối thiểu dữ liệu):** Chỉ ghi nhận `ts`, `device_id`, `child_id`, `type`, `subject`, `duration_sec`, `policy_id`. Trường `subject` chỉ được là tên file `.exe` (`chrome.exe`) hoặc tên miền (`youtube.com`). **Cấm tuyệt đối** lưu URL đầy đủ, tiêu đề cửa sổ, phím bấm (keylogger) hay ảnh chụp màn hình.
3. **NT3 (Trẻ có tiếng nói):** Trẻ có nút **"Xin thêm giờ"** (`unlock_request`) và **"Em nghĩ trang này bị chặn nhầm"** (`false_positive_report`), có phản hồi trực tiếp từ phụ huynh.
4. **NT4 (Giải thích được):** Mọi luật chặn app/web bắt buộc đính kèm `reason` (lý do) và `created_by` (người đặt luật); khi chặn phải bật popup giải thích rõ ràng.
5. **NT5 (Minh bạch hai chiều):** Trẻ dùng tài khoản `child-view` xem được chính xác báo cáo sử dụng và toàn bộ nhật ký thay đổi luật (`audit_logs`) của phụ huynh.
6. **NT6 (An toàn ưu tiên tuyệt đối):** Khóa cứng danh sách miễn chặn vĩnh viễn gồm Tổng đài bảo vệ trẻ em **111**, cứu hộ **113/114/115**, và các cổng giáo dục (`tongdai111.vn`, `111.gov.vn`, `moet.gov.vn`, `olm.vn`, `vio.edu.vn`, `vnedu.vn`…).

---

## 2. Kiến trúc hệ thống & Luồng giao tiếp tổng quan

```text
MÁY CỦA TRẺ (Windows 10/11)                         OGK SERVER (FastAPI + SQLite WAL)
┌────────────────────────────────────┐   HTTPS      ┌─────────────────────────────────┐
│ Windows Service (LocalSystem)      │  TLS 1.2+    │ REST API /api/v1/*              │
│  • DNS Proxy 127.0.0.1:53          │◄────────────►│  • /auth, /enroll, /policy      │
│  • App Controller (psutil+SHA-256) │ Heartbeat 60s│  • /heartbeat, /events/batch    │
│  • Time Tracker (time.monotonic)   │              │  • /reports, /requests          │
│  • Local SQLite (ProgramData ACL)  │  WebSocket   │ WebSocket /ws/device/{id}       │
│  • Local IPC 127.0.0.1:47891       │◄────────────►│  • Lệnh khẩn < 5s               │
└──────────────▲─────────────────────┘              └────────────────▲────────────────┘
               │ Local HTTP + IPC Token                              │ HTTPS + Cookie/CSRF
┌──────────────▼─────────────────────┐              ┌────────────────▼────────────────┐
│ Tray UI (Quyền User — Bạn B)       │              │ Web Dashboard (Mobile — Bạn B)  │
│  • Đồng hồ còn lại, Popup NT4      │              │  • Phụ huynh (/) & Trẻ (/child- │
│  • Nút Xin thêm giờ / Báo chặn nhầm│              │    view)                        │
└────────────────────────────────────┘              └─────────────────────────────────┘
```

Chi tiết 7 luồng hoạt động (Enrollment, Policy HMAC, Heartbeat chống chỉnh đồng hồ, DNS Proxy, App SHA-256, Lệnh khẩn `< 5s`, Offline & Purge) được vẽ sơ đồ đầy đủ tại [docs/TEAM_GUIDE.md](./docs/TEAM_GUIDE.md).

---

## 3. Tổng hợp chi tiết NHỮNG GÌ ĐÃ LÀM XONG vs CẦN LÀM TIẾP

### Đã hoàn thiện 100% & đã kiểm chứng chạy thực tế
| Hạng mục | Thư mục / Tệp | Chi tiết đã hoàn thành | Trạng thái |
|---|---|---|---|
| **Hợp đồng API & Schema chung** | `contracts/api_contract.md`, `contracts/shared_schemas.py` | Đặc tả toàn bộ REST API, WebSocket và Local IPC `127.0.0.1:47891`; hàm ký & xác thực `HMAC-SHA256` canonical JSON; bộ kiểm định NT2 & NT6 dùng chung cho cả Server và Agent. | **Xong 100%** |
| **Bộ dữ liệu 220+ tên miền an toàn** | `data/domain_categories.json`, `data/default_policy_6_11.json` | 220 tên miền chia 6 nhóm + 5 DoH canary + 5 DoH endpoints + 50 test domains + 10 miền mô phỏng bị chặn (chỉ dùng `.example.*`, 0 miền người lớn thật) + chính sách mặc định 6–11 tuổi. | **Xong 100%** |
| **Backend Server hoàn chỉnh** | `server/app/*`, `server/seed.py` | FastAPI + SQLite chế độ WAL (`foreign_keys=ON`): Argon2id (khóa 15p sau 5 lần sai), AES-256-GCM, Cookie `HttpOnly`/`SameSite=Lax` + CSRF, Anti-IDOR ở tầng query, mã ghép đôi 8 ký tự (10p), Heartbeat phát hiện lệch đồng hồ `>120s`, Policy HMAC, WebSocket lệnh khẩn, Batch events chống trùng `idempotency_key`, Báo cáo + Xuất CSV/PDF + Nút Purge, Background worker tự xóa dữ liệu `>90 ngày`. | **Xong 100%** |
| **Bộ kiểm thử tự động (`pytest`)** | `tests/*` | **22/22 test PASS** (17 unit/component tests + 5 kịch bản tích hợp E2E về bảo mật, chống IDOR, HMAC, chỉnh đồng hồ, NT2/NT4/NT5/NT6, retention 90 ngày, WebSocket & Purge). | **Xong 100%** |
| **Web Dashboard (bản MVP chạy thật)** | `dashboard/templates/*`, `dashboard/static/parent.js` | Dashboard Phụ huynh 5 tab nối API thật (biểu đồ Chart.js, lịch `7×48` kéo chọn được, chặn Web/App có NT4/NT6, mã ghép đôi, nút khẩn cấp, duyệt NT3, Audit Log NT5, CSV/PDF/Purge) + Trang `/child-view` cơ bản cho trẻ. | **Xong khung MVP (~75%)** |
| **Khung code Agent & Tài liệu nền** | `agent/*`, `docs/PRIVACY.md`, `docs/THREATMODEL.md`, `docs/TEAM_GUIDE.md` | Khung class/interface & docstring đầy đủ cho toàn bộ module Agent; bản nháp hoàn chỉnh `PRIVACY.md` (có bản trẻ đọc) & `THREATMODEL.md` (9 mối đe dọa STRIDE + ASVS). | **Xong khung chuẩn** |

### Các hạng mục nhóm cần code & thực nghiệm tiếp
1. **Bạn A (`/agent/service/`):** Hiện thực logic thật bên trong 6 file khung (`dns_proxy.py`, `app_controller.py`, `time_tracker.py`, `local_store.py`, `ipc_server.py`, `windows_service.py`) và chạy thực nghiệm báo cáo **M1, M2, M3, M6**.
2. **Bạn B (`/dashboard/` & `/agent/tray_ui/`):** Nâng cấp hoàn thiện Web Dashboard (ngân sách 6 nhóm danh mục, tìm nhanh 220 domain, tối ưu mobile), code **Windows Tray UI** (`main_tray.py` dùng `pystray` + `tkinter`), đo hiệu năng **M4**, chịu lỗi **M5**, quay **Video Demo 5–7 phút**.
3. **Bạn — Leader (`/server`, `/tests`, `/docs`):** Bật **TLS 1.2+** tự ký + Certificate Pinning cho môi trường lab, hỗ trợ ghép nối 3 phần, hoàn thiện `BaoCao.docx` + `BaoCaoKyThuatMang.pdf` + `AI_USAGE.md`.

---

## 4. Chạy thử ngay trên máy của bạn trong 5 phút

```powershell
# 1. Tạo môi trường ảo và cài thư viện
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r server/requirements.txt

# 2. Khởi tạo cơ sở dữ liệu mẫu (SQLite WAL + 236 domain + 4 tài khoản demo)
python server/seed.py

# 3. Chạy bộ kiểm thử tự động (phải ra 22 passed)
pytest tests/ -v

# 4. Khởi động OGK Server
uvicorn server.app.main:app --host 0.0.0.0 --port 8000 --reload
```

Mở trình duyệt:
- **Dashboard Phụ huynh:** `http://127.0.0.1:8000/` (`parent@ogk.local` / `ParentPass2026!`)
- **Góc minh bạch cho trẻ:** `http://127.0.0.1:8000/child-view` (`child@ogk.local` / `ChildView2026!`)
- **Tài liệu API Swagger:** `http://127.0.0.1:8000/docs`

> Xem hướng dẫn làm việc Git, phân công chi tiết từng thành viên và prompt hỗ trợ code tại **[HUONG_DAN_LAM_VA_CHIA_VIEC.md](./HUONG_DAN_LAM_VA_CHIA_VIEC.md)**.
