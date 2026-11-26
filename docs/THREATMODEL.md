# Mô hình Mối đe dọa & Checklist Bảo mật (THREATMODEL.md)

Tài liệu phân tích **STRIDE** tối thiểu 8 mối đe dọa trọng yếu (bao gồm kịch bản *chính trẻ là người tấn công* và *lạm dụng làm stalkerware*) cùng kiểm chứng OWASP ASVS cấp cơ bản cho hệ thống OGK.

## 1. Phạm vi sử dụng hợp pháp (Anti-Abuse Statement)
OGK được thiết kế **duy nhất** để cha mẹ/người giám hộ hợp pháp đồng hành quản lý máy tính của trẻ em dưới 16 tuổi một cách công khai, minh bạch. Sản phẩm **cấm** cài đặt ẩn để theo dõi người lớn (stalkerware): không có chế độ ẩn biểu tượng; nếu không hiển thị được Tray UI trong phiên người dùng, Service phải ngừng thực thi ngầm và ghi cảnh báo kiểm toán.

## 2. Bảng phân tích STRIDE (9 mối đe dọa trọng yếu)

| # | Loại STRIDE | Kịch bản mối đe dọa | Tác nhân | Biện pháp giảm thiểu trong mã nguồn OGK | Giới hạn còn lại |
|---|---|---|---|---|---|
| T1 | **Spoofing** | Kẻ tấn công thử dò mật khẩu phụ huynh trên trang đăng nhập Dashboard | Bên ngoài / Trẻ | Băm mật khẩu **Argon2id**, yêu cầu ≥10 ký tự, khóa tạm **15 phút** sau 5 lần sai (`server/app/api/auth.py`), giới hạn tần suất theo IP. | Nên bật thêm TOTP 2FA ở bản nâng cao. |
| T2 | **Tampering** | Chính trẻ (hoặc MITM trong mạng LAN) sửa gói tin `Policy` hoặc sửa file SQLite cục bộ để tự tăng quota | Trẻ / MITM LAN | Kênh truyền TLS 1.2+ kèm **Certificate Pinning**; mọi Policy được ký **HMAC-SHA256** theo canonical JSON (`verify_policy_signature()`). Thư mục `C:\ProgramData\OGK` đặt ACL chỉ `SYSTEM`/`Administrators` được ghi. | Nếu trẻ có quyền Administrator cục bộ thì có thể thay đổi ACL/dịch vụ. |
| T3 | **Tampering** | Trẻ lùi đồng hồ hệ thống Windows 3 giờ để kéo dài thời gian sử dụng | Trẻ | Đếm thời gian bằng `time.monotonic()` (`agent/service/time_tracker.py`); mỗi heartbeat 60s đối chiếu `abs(server_ts - device_ts) > 120s` và ghi `CLOCK_SKEW_DETECTED` vào `audit_logs` (`server/app/api/heartbeat.py`). | — |
| T4 | **Repudiation** | Phụ huynh thay đổi luật chặn đột ngột hoặc có tranh cãi về lịch sử thay đổi | Phụ huynh / Nội bộ | Mọi cập nhật Policy, lệnh khẩn, duyệt yêu cầu đều ghi `audit_logs` (ai, lúc nào, IP, giá trị cũ/mới) và **trẻ được quyền xem** (NT5). | — |
| T5 | **Information Disclosure (IDOR)** | Phụ huynh A sửa tham số `child_id` hoặc `device_id` trong URL API để xem báo cáo hoặc khóa máy con của Phụ huynh B | Người dùng ác ý | Kiểm tra quyền sở hữu ở tầng truy vấn (`get_authorized_child`, `get_authorized_device` trong `server/app/core/security.py`), không bao giờ chỉ ẩn nút trên giao diện. | — |
| T6 | **Information Disclosure (Privacy)** | Agent gửi nhầm full URL, tham số tìm kiếm hoặc tiêu đề cửa sổ về Server | Lỗi phần mềm / Sửa Agent | Kiểm định nghiêm ngặt NT2 tại `TelemetryEventItem` (`contracts/shared_schemas.py`): từ chối `422` mọi `subject` chứa `http://`, `/`, `?`, `=`, khoảng trắng. Mã hóa bí mật bằng **AES-256-GCM**. Tự động xóa dữ liệu > 90 ngày. | — |
| T7 | **Denial of Service / Bypass** | Trẻ đổi tên `game.exe` thành `notepad.exe`, tắt tiến trình Agent, hoặc bật DNS-over-HTTPS (DoH) trong trình duyệt | Trẻ | Đối chiếu ứng dụng bằng **SHA-256** tệp `.exe`; Service chạy dưới `LocalSystem` có SCM Recovery tự khởi động lại; DNS Proxy chặn DoH endpoints & trả `NXDOMAIN` cho tên miền canary (`use-application-dns.net`). | Trẻ dùng VPN mã hóa cổng 443 hoặc boot USB ngoài phạm vi DNS proxy (phân tích chi tiết trong mục M3). |
| T8 | **Elevation of Privilege / CSRF** | Trang web độc hại kích hoạt trình duyệt của phụ huynh gửi lệnh `DELETE /purge` hoặc `PUT /policy` trái phép | Website độc hại | Cookie `HttpOnly`, `Secure`, `SameSite=Lax`, hủy phiên server-side khi logout, và bắt buộc header `X-CSRF-Token` trên mọi thao tác ghi (`require_csrf`). | — |
| T9 | **Abuse as Stalkerware** | Kẻ xấu lợi dụng OGK để theo dõi vợ/chồng hoặc người lớn bí mật | Kẻ lạm dụng | Cấm chế độ ẩn (NT1): Tray UI luôn hiển thị và gửi `/ipc/tray-heartbeat` mỗi 10s; nếu không hiện được icon, Service tự dừng và ghi `NT1_TRAY_NOT_VISIBLE_ALERT`. Trẻ/người dùng cuối có tài khoản `child-view` xem cùng báo cáo và audit log (NT5). | Cần đảm bảo quy trình cài đặt luôn hiển thị màn hình thông báo minh bạch. |

## 3. Checklist kiểm chứng OWASP ASVS (Cơ bản)
- [x] **V2 Authentication:** Argon2id, mật khẩu ≥10 ký tự, lockout 5 lần / 15 phút.
- [x] **V3 Session Management:** Cookie `HttpOnly`, `Secure` (khi bật TLS), `SameSite=Lax`, timeout 12 giờ, hủy phiên phía server.
- [x] **V4 Access Control:** RBAC 3 vai trò (`parent`, `child-view`, `admin`), kiểm tra quyền sở hữu ở tầng DB query chống IDOR, kiểm thử tự động trong `tests/test_security_auth.py`.
- [x] **V5 Validation:** Pydantic v2 validation + NT2 strict subject validator + NT6 immutable emergency whitelist.
- [x] **V6 Cryptography:** AES-256-GCM cho bí mật lưu trữ, HMAC-SHA256 cho Policy, SHA-256 cho token hashes, không hardcode khóa sản xuất.
- [x] **V7 Logging & Auditing:** `audit_logs` lưu ai/khi nào/IP/giá trị cũ-mới, không log mật khẩu hay token.
