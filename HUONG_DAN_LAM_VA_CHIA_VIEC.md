# HƯỚNG DẪN LÀM VIỆC NHÓM & PHÂN CÔNG 3 THÀNH VIÊN

Tài liệu này quy định **quy trình Git**, **ranh giới thư mục không chồng chéo**, **checklist đầu việc cụ thể**, **prompt mẫu hỗ trợ code** và **lộ trình 6 tuần** cho nhóm 03 sinh viên.

---

## 1. Quy tắc Git để 3 người KHÔNG BAO GIỜ bị conflict

1. **Mỗi thành viên chỉ làm việc trên nhánh riêng và đúng thư mục của mình:**
   - **Leader (Bạn):** nhánh `feat/server-security` → chỉ sửa `/server`, `/contracts`, `/tests`, `/docs/THREATMODEL.md`.
   - **Bạn A (Agent Core):** nhánh `feat/agent-service` → chỉ sửa `/agent/service/*`.
   - **Bạn B (UI & Tray):** nhánh `feat/ui-tray` → chỉ sửa `/dashboard/*`, `/agent/tray_ui/*`, `/docs/PRIVACY.md`.
2. **Không tự ý sửa file trong `contracts/`:** Nếu cần thêm trường API hoặc đổi cổng IPC, phải nhắn cả nhóm thống nhất và để Leader cập nhật rồi mọi người `git pull origin main`.
3. **Lệnh Git cơ bản hằng ngày:**
   ```powershell
   # Lần đầu lấy code về
   git clone https://github.com/thienhcmustnt/ogk-starter.git
   cd ogk-starter
   git checkout -b feat/<ten-nhanh-cua-ban>

   # Trước khi code mỗi ngày: cập nhật mới nhất từ main
   git fetch origin
   git merge origin/main

   # Khi xong 1 chức năng: đẩy nhánh lên và tạo Pull Request vào main
   git add .
   git commit -m "feat(agent): implement DNS proxy SafeSearch and NT6 whitelist"
   git push -u origin feat/<ten-nhanh-cua-ban>
   ```

---

## 2. Phân công chi tiết cho 3 thành viên

### THÀNH VIÊN 1 — LEADER (Bạn): Server, Bảo mật, Tích hợp & Tài liệu Kiến trúc (~34%)
- **Thư mục phụ trách:** `server/`, `contracts/`, `tests/`, `docs/THREATMODEL.md`, `docs/AI_USAGE.md`.
- **Checklist công việc:**
  1. Tạo chứng chỉ **TLS 1.2+** tự ký (self-signed cert) cho môi trường lab, bật `OGK_COOKIE_SECURE=true`, xuất mã băm **SHA-256 Certificate Pinning** gửi cho Bạn A.
  2. Chạy Server trên máy LAN (hoặc VPS lab) và chia sẻ địa chỉ `https://<IP>:8443/docs` cho Bạn A & Bạn B kiểm thử tích hợp.
  3. Bổ sung endpoint tiện ích nếu nhóm cần (VD: tạo thêm hồ sơ con, xác thực mật khẩu phụ huynh khi gỡ cài đặt hợp pháp F4).
  4. Rà soát & cập nhật `pytest` khi ghép Agent và UI (đảm bảo luôn giữ `≥ 15` unit test và `≥ 5` integration test PASS).
  5. Viết phần kiến trúc hệ thống, đặc tả giao thức mục 4.3, biện luận chính sách hết hạn offline (`fail_open_with_education_only`), hoàn thiện `docs/THREATMODEL.md` và `docs/AI_USAGE.md`.

---

### THÀNH VIÊN 2 — BẠN A: Windows Agent Service & Kỹ thuật Mạng (~34%)
- **Thư mục phụ trách:** `agent/service/*` (6 file khung đã có sẵn chữ ký hàm & docstring).
- **Tài liệu cần đọc trước:** `contracts/api_contract.md` (Mục 2–6, 9) và `contracts/shared_schemas.py`.
- **Checklist code chi tiết:**
  1. **`dns_proxy.py` (DNS Proxy `127.0.0.1:53` UDP/TCP):**
     - Luôn cho qua `NT6_IMMUTABLE_WHITELIST_DOMAINS` (`111.gov.vn`, `tongdai111.vn`, `olm.vn`, `moet.gov.vn`…).
     - Trả `NXDOMAIN` cho 5 tên miền DoH canary (`use-application-dns.net`…) và chặn 5 DoH endpoints (`dns.google`, `cloudflare-dns.com`…) khi bật `block_doh_endpoints`.
     - Ép **SafeSearch** (`google.com` → `forcesafesearch.google.com`, `bing.com` → `strict.bing.com`, `duckduckgo.com` → `safe.duckduckgo.com`).
     - Chặn tên miền & toàn bộ subdomain theo `blocked_domains` và `category_rules` (đạt `≥ 95%` trên 50 tên miền kiểm thử, **0 dương tính giả** trên 20 tên miền giáo dục).
     - Khi chặn: đẩy `LocalIPCBlockNotice` (kèm `reason`, `created_by`) sang Tray UI và ghi sự kiện NT2 (`blocked_domain`, chỉ lưu tên miền).
  2. **`app_controller.py` (Kiểm soát tiến trình & SHA-256):**
     - Quét tiến trình bằng `psutil`, tính & cache **SHA-256** file `.exe` (đổi tên `notepad.exe` ↔ `game.exe` vẫn nhận diện đúng).
     - Không bao giờ tắt `NT6_IMMUTABLE_WHITELIST_APPS`.
     - Kill tiến trình bị cấm, bắn popup NT4 sang Tray UI và ghi sự kiện `blocked_app`.
  3. **`time_tracker.py` (Đếm giờ chống chỉnh đồng hồ):**
     - Dùng **`time.monotonic()`** (lùi đồng hồ Windows 3 giờ không làm tăng quota).
     - Dừng đếm khi máy khóa hoặc không thao tác > 5 phút (`GetLastInputInfo`).
     - Kiểm tra ma trận `7×48` theo mốc thời gian đồng bộ từ Server (khóa trong 5s khi ra ngoài khung giờ).
     - Cảnh báo trước **10, 5, 1 phút** và khoảng ân hạn **60 giây** để trẻ lưu bài.
  4. **`local_store.py` (Bộ đệm Offline SQLite):**
     - Lưu tại `C:\ProgramData\OGK\agent_cache.db` (đặt ACL bằng `icacls` chỉ `SYSTEM` và `Administrators` có quyền ghi).
     - Gọi `verify_policy_signature()` trước khi nạp/lưu Policy; đệm sự kiện offline kèm `idempotency_key` và đồng bộ theo lô khi có mạng; xóa sạch cache khi nhận lệnh `PURGE_CACHE`.
  5. **`ipc_server.py` & `windows_service.py`:**
     - Chạy Local HTTP `127.0.0.1:47891` xác thực bằng `X-OGK-IPC-Token` cho Bạn B gọi.
     - Đóng gói thành Windows Service (`LocalSystem`) có SCM Recovery tự khởi động lại; giám sát `tray-heartbeat` (nếu Tray UI không hiện > 30s thì ngừng thực thi ngầm theo NT1).
     - Kết nối Server qua HTTPS (có **Certificate Pinning**), gọi `POST /heartbeat` mỗi 60s và giữ kết nối WebSocket `/ws/device/{id}`.
- **Phần Báo cáo kỹ thuật (`BaoCaoKyThuatMang.pdf`) của Bạn A:**
  - **M1:** Sơ đồ luồng gói tin DNS + ảnh chụp Wireshark truy vấn và phản hồi bị chặn.
  - **M2:** Bảng so sánh 4 phương án (file `hosts` / DNS proxy / HTTP(S) proxy / WFP) theo 5 tiêu chí.
  - **M3:** Thực nghiệm tối thiểu **7 kỹ thuật bypass** (đổi DNS thủ công, DoH, DoT, VPN, truy cập bằng IP, Safe Mode, boot USB, đổi tài khoản Windows, kill tiến trình).
  - **M6:** Giải thích & chứng minh cơ chế `time.monotonic()` + đối chiếu `server_ts` ngưỡng 120s.

#### Prompt mẫu dành riêng cho Bạn A (copy đưa AI hỗ trợ code):
```text
Bạn là Senior Windows Systems & Network Engineer. Hãy đọc contracts/api_contract.md, contracts/shared_schemas.py và data/domain_categories.json, sau đó hiện thực đầy đủ các file khung trong thư mục agent/service/:
1. dns_proxy.py: UDP/TCP DNS proxy tại 127.0.0.1:53 dùng dnslib, ưu tiên NT6 whitelist -> DoH canary/endpoint -> SafeSearch CNAME -> Allow/Block domain & subdomain (kèm test unit với 50 tên miền trong data/domain_categories.json đạt 0 dương tính giả trên 20 miền giáo dục).
2. app_controller.py: Quét tiến trình bằng psutil, tính & cache SHA-256 tệp .exe để chống đổi tên file, terminate tiến trình bị cấm và gửi LocalIPCBlockNotice (NT4).
3. time_tracker.py: Đếm giờ bằng time.monotonic(), bỏ qua thời gian idle > 5 phút (ctypes GetLastInputInfo) hoặc máy khóa, đánh giá ma trận lịch 7x48, cảnh báo 10/5/1 phút + ân hạn 60s.
4. local_store.py: SQLite cache tại C:\ProgramData\OGK\agent_cache.db (hỗ trợ custom path cho test), luôn verify HMAC-SHA256 qua contracts.shared_schemas.verify_policy_signature(), hàng đợi sync offline có idempotency_key và hàm purge_local_cache().
5. ipc_server.py & windows_service.py: HTTP cục bộ 127.0.0.1:47891 bảo vệ bởi X-OGK-IPC-Token theo Mục 9 của api_contract.md, vòng lặp heartbeat 60s + WebSocket /ws/device/{id} + Windows Service win32serviceutil có kiểm tra tray_visible (NT1).
```

---

### THÀNH VIÊN 3 — BẠN B: Web Dashboard, Windows Tray UI & Thực nghiệm (~32%)
- **Thư mục phụ trách:** `dashboard/*`, `agent/tray_ui/main_tray.py`, `docs/PRIVACY.md`.
- **Tài liệu cần đọc trước:** `dashboard/HANDOFF_BAN_B.md` và `contracts/api_contract.md` (Mục 1–3, 5, 7–9).
- **Checklist code chi tiết:**
  1. **Nâng cấp Web Dashboard (`dashboard/`):**
     - Từ bản MVP đã chạy sẵn, bổ sung mục chỉnh **ngân sách thời gian theo 6 nhóm danh mục** (`category_rules`), ô tìm kiếm nhanh 220+ tên miền từ `GET /api/v1/policy/domains/catalog`.
     - Kiểm thử hiển thị mượt trên trình duyệt điện thoại (390×844px).
     - Làm đẹp trang `/child-view` cho học sinh cấp 1: thêm minh họa thân thiện và gợi ý **nghỉ mắt 20-20-20**.
  2. **Hiện thực Windows Tray UI (`agent/tray_ui/main_tray.py`):**
     - Chạy dưới quyền user bình thường, dùng `pystray` tạo icon **bắt buộc luôn hiện** (không tạo được icon phải báo lỗi & dừng theo NT1).
     - Gửi `POST http://127.0.0.1:47891/ipc/tray-heartbeat` mỗi 10s, poll `/ipc/status` & `/ipc/notifications`.
     - Hiển thị popup cảnh báo còn **10, 5, 1 phút** + đếm ngược ân hạn **60 giây**.
     - Hiển thị cửa sổ **Giải thích lý do chặn (NT4)** bằng `tkinter` (tên app/web, lý do, người đặt luật) kèm 2 nút **"Xin thêm giờ"** và **"Em nghĩ trang này bị chặn nhầm"** (NT3).
     - Menu khay hệ thống mở nhanh *"Hôm nay em đã dùng gì"*, *"Ứng dụng này ghi nhận gì về em"*, và thông tin **Tổng đài 111**.
- **Phần Báo cáo & Sản phẩm của Bạn B:**
  - Hoàn thiện `docs/PRIVACY.md` (bảng từng trường dữ liệu + bản dành cho trẻ tiểu học).
  - Đo hiệu năng **M4** (tối thiểu 30 mẫu: CPU/RAM lúc rảnh & cao điểm, DNS latency p50/p95 có và không có Agent, độ trễ đồng bộ Policy từ Dashboard tới máy trẻ).
  - Kiểm thử chịu lỗi **M5** (3 kịch bản: mất mạng, tắt Server, kết thúc tiến trình Agent — ghi hành vi mong đợi, thực tế, thời gian phục hồi).
  - Quay và dựng **Video Demo 5–7 phút** (`demo/video.mp4`) có thuyết minh/phụ đề tiếng Việt.

*(Prompt mẫu chi tiết cho Bạn B đã nằm sẵn trong [dashboard/HANDOFF_BAN_B.md](./dashboard/HANDOFF_BAN_B.md).)*

---

## 3. Lộ trình 6 tuần để về đích đúng hạn

| Tuần | Mốc hoàn thành (Milestone) | Người chịu trách nhiệm chính |
|---|---|---|
| **Tuần 1** | Chốt kiến trúc, hoàn thiện `/server`, `seed.py`, `contracts/`, Dashboard MVP, 22 tests PASS, đẩy Git và chia nhánh. | **Leader** *(đã xong 95%)* |
| **Tuần 2** | Bạn A xong `dns_proxy.py` + `app_controller.py` + `local_store.py`; Bạn B xong nâng cấp Web Dashboard + khung `tkinter`/`pystray` với mock IPC; Leader bật TLS + Cert Pinning. | **Cả 3 người song song** |
| **Tuần 3** | Bạn A xong `time_tracker.py` + `ipc_server.py` + `windows_service.py`; Bạn B hoàn thiện `main_tray.py` đầy đủ popup NT4/NT3 & `/child-view`. | **Bạn A & Bạn B** |
| **Tuần 4** | **Tuần ghép nối (Integration):** Nối Tray UI ↔ Service ↔ Server TLS trên máy Windows thật (tài khoản trẻ Standard User); nghiệm thu đủ tiêu chí F1–F5. | **Cả 3 người** |
| **Tuần 5** | **Đóng băng tính năng (Feature Freeze):** Bắt Wireshark (M1), test 7+ bypass (M3), đo 30 mẫu hiệu năng (M4), test chịu lỗi (M5); hoàn thiện `BaoCao.docx` (20–30 trang) & `BaoCaoKyThuatMang.pdf`. | **Cả 3 người** |
| **Tuần 6** | Quay video demo 5–7 phút (`demo/video.mp4`), diễn tập cài sạch từ đầu `< 15 phút` đúng `README.md`, tập dượt hỏi đáp chéo dựa theo 6 câu hỏi trong `docs/TEAM_GUIDE.md`. | **Cả 3 người** |

---

## 4. Checklist sản phẩm nộp cuối kỳ (Mục 8 đề bài)
- [ ] `/agent`, `/server`, `/dashboard`, `/tests` (≥ 15 unit test + ≥ 5 integration test, kèm ảnh chụp `pytest`)
- [ ] `/docs/BaoCao.docx` (20–30 trang, có bảng phân công & tự đánh giá % đóng góp)
- [ ] `/docs/BaoCaoKyThuatMang.pdf` (đủ **M1–M6** — trọng tâm chấm điểm)
- [ ] `/docs/PRIVACY.md`, `/docs/THREATMODEL.md`, `/docs/AI_USAGE.md`
- [ ] `/demo/video.mp4` (5–7 phút, thuyết minh/phụ đề tiếng Việt)
- [ ] `/README.md` (cài được trong `< 15 phút` trên máy Windows sạch)
