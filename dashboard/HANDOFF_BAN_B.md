# Hướng dẫn bàn giao cho Thành viên B (`/dashboard` & `/agent/tray_ui`)

Phần khung Web Dashboard Phụ huynh và Góc minh bạch cho trẻ đã chạy được cơ bản trên FastAPI Server.
Bạn B chỉ cần làm việc trong 2 thư mục:
1. `dashboard/` (`templates/index.html`, `templates/child_transparency.html`, `static/parent.js`)
2. `agent/tray_ui/` (`main_tray.py`)

---

## 1. Những gì đã có sẵn để chạy thử ngay
Chạy server trên máy bạn hoặc kết nối IP LAN của Leader:
```powershell
.\.venv\Scripts\uvicorn.exe server.app.main:app --host 0.0.0.0 --port 8000 --reload
```
- `http://127.0.0.1:8000/`: Dashboard Phụ huynh đã nối sẵn API thật (Đăng nhập, biểu đồ 7 ngày Chart.js, Ma trận lịch `7×48` kéo chọn được, thêm/gỡ chặn Web/App có NT4/NT6, tạo mã ghép đôi 8 ký tự, nút khẩn cấp `LOCK_NOW`/`UNLOCK_NOW`/`ADD_15M`/`PAUSE_2H`, duyệt yêu cầu NT3, xem Audit Logs NT5, xuất CSV/PDF, nút Purge).
- `http://127.0.0.1:8000/child-view`: Góc minh bạch cho tài khoản `child@ogk.local` / `ChildView2026!`.

---

## 2. Checklist đầu việc Bạn B cần hoàn thiện

### A. Nâng cấp Web Dashboard (`/dashboard`)
- [ ] Thêm phần cấu hình **Ngân sách theo 6 nhóm danh mục** (`category_rules`: giáo dục không giới hạn, trò chơi 30p, mạng xã hội chặn…) — backend đã hỗ trợ sẵn trong `PUT /api/v1/policy/{child_id}`.
- [ ] Thêm hộp tra cứu nhanh 220+ tên miền từ `GET /api/v1/policy/domains/catalog` để phụ huynh chọn chặn nhanh mà không cần gõ tay.
- [ ] Tối ưu giao diện trên màn hình điện thoại (test bằng Chrome DevTools responsive 390×844px) và thêm minh họa thân thiện cho trẻ tiểu học ở `/child-view` (gợi ý nghỉ mắt quy tắc **20-20-20**).

### B. Hoàn thiện Windows Tray UI (`/agent/tray_ui/main_tray.py`)
Giao tiếp cục bộ với Windows Service của Bạn A qua `http://127.0.0.1:47891` + header `X-OGK-IPC-Token` (xem chi tiết tại `contracts/api_contract.md` Mục 9):
- [ ] Biểu tượng khay hệ thống `pystray` **bắt buộc luôn hiển thị** (nếu tạo icon thất bại phải dừng thoát để đảm bảo chống stalkerware NT1).
- [ ] Thread nền gửi `POST /ipc/tray-heartbeat` mỗi 10s và poll `GET /ipc/status` + `GET /ipc/notifications`.
- [ ] Popup cảnh báo còn **10, 5, 1 phút** và đồng hồ đếm ngược ân hạn **60 giây**.
- [ ] Cửa sổ **Giải thích lý do chặn (NT4)** bằng `tkinter`: hiện tên app/web, lý do, người đặt luật, kèm 2 nút **"Xin thêm giờ"** và **"Em nghĩ trang này bị chặn nhầm"** gọi `POST /ipc/request`.
- [ ] Menu chuột phải trên icon khay hệ thống: *"Hôm nay em đã dùng gì"*, *"Ứng dụng này ghi nhận gì về em"*, *"Tổng đài bảo vệ trẻ em 111"*.

### C. Tài liệu & Thực nghiệm của Bạn B
- [ ] Rà soát & trình bày đẹp `docs/PRIVACY.md` (kèm bản trẻ đọc).
- [ ] Khi ghép hệ thống ở Tuần 4–5: đo **M4** (≥30 mẫu CPU/RAM/DNS latency/Policy latency) và kiểm thử chịu lỗi **M5** (mất mạng, server sập, kill agent).
- [ ] Quay & dựng **Video Demo 5–7 phút** có thuyết minh tiếng Việt.

---

## 3. Prompt mẫu Bạn B có thể đưa cho AI hỗ trợ code tiếp

```text
Hãy hoàn thiện giúp tôi 2 phần trong đồ án OGK (đọc contracts/api_contract.md và contracts/shared_schemas.py trước):
1. Nâng cấp dashboard/templates/index.html, dashboard/static/parent.js và dashboard/templates/child_transparency.html:
   - Thêm UI chỉnh ngân sách thời gian cho 6 nhóm danh mục (`category_rules`) và ô tìm kiếm nhanh tên miền từ GET /api/v1/policy/domains/catalog.
   - Đảm bảo giao diện mượt trên điện thoại (mobile responsive) và bổ sung banner nhắc nghỉ mắt 20-20-20 ở /child-view.
2. Hiện thực hoàn chỉnh agent/tray_ui/main_tray.py bằng Python (pystray + tkinter + httpx):
   - Đọc token từ C:\ProgramData\OGK\ipc_token.txt (có chế độ mock local để test độc lập khi chưa chạy Service của Bạn A).
   - Hiển thị icon khay hệ thống bắt buộc (NT1), gửi POST /ipc/tray-heartbeat mỗi 10s, poll /ipc/status và /ipc/notifications.
   - Tạo cửa sổ tkinter giải thích lý do chặn (NT4) với 2 nút "Xin thêm giờ" và "Em nghĩ trang này bị chặn nhầm" (NT3), cùng màn hình "Ứng dụng này ghi nhận gì về em" bằng ngôn ngữ học sinh tiểu học.
```
