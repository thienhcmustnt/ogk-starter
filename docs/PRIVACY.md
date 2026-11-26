# Chính sách Quyền riêng tư & Tối thiểu hóa Dữ liệu (PRIVACY.md)

Tài liệu này cụ thể hóa **Nguyên tắc NT2 (Tối thiểu dữ liệu)**, **NT5 (Minh bạch hai chiều)** và **Nghị định 13/2023/NĐ-CP** về bảo vệ dữ liệu cá nhân của trẻ em trong hệ thống OGK.

---

## Phần 1: Bảng kiểm soát từng trường dữ liệu (Dành cho Phụ huynh & Giảng viên kiểm định)

Mọi trường không giải thích được mục đích đều đã bị loại bỏ khỏi lược đồ cơ sở dữ liệu.

| Trường dữ liệu | Bảng lưu trữ | Mục đích xử lý duy nhất | Thời hạn lưu trữ | Ai xem được |
|---|---|---|---|---|
| `ts` | `events` | Ghi mốc thời gian sự kiện để vẽ biểu đồ theo ngày/tuần | Tự động xóa sau **90 ngày** (hoặc xóa ngay khi phụ huynh bấm Purge) | Phụ huynh sở hữu & Trẻ (`child-view`) |
| `device_id` | `events`, `devices` | Phân biệt máy tính nào phát sinh sự kiện (mô hình 1 phụ huynh : n trẻ : m máy) | Đến khi thu hồi thiết bị / 90 ngày với event | Phụ huynh sở hữu & Trẻ (`child-view`) |
| `child_id` | `events`, `policies`, `audit_logs` | Gắn dữ liệu với hồ sơ trẻ tương ứng để kiểm soát quyền (chống IDOR) | Theo vòng đời hồ sơ | Phụ huynh sở hữu & Trẻ (`child-view`) |
| `type` | `events` | Phân loại 9 nhóm sự kiện hợp lệ (`app_start`, `blocked_domain`, `unlock_request`...) | 90 ngày | Phụ huynh sở hữu & Trẻ (`child-view`) |
| `subject` | `events` | **Chỉ** lưu tên tệp thực thi (`chrome.exe`) hoặc tên miền cấp hai (`youtube.com`). Server từ chối mã `422` nếu phát hiện URL đầy đủ, query string hoặc đường dẫn tệp. | 90 ngày | Phụ huynh sở hữu & Trẻ (`child-view`) |
| `duration_sec` | `events` | Tính tổng thời lượng sử dụng theo ngày/tuần | 90 ngày | Phụ huynh sở hữu & Trẻ (`child-view`) |
| `policy_id` | `events` | Giải thích sự kiện phát sinh dưới phiên bản luật nào (NT4) | 90 ngày | Phụ huynh sở hữu & Trẻ (`child-view`) |
| `audit_logs` (`actor_label`, `action`, `ip_address`, `old_value`, `new_value`) | `audit_logs` | Minh bạch mọi thay đổi chính sách của phụ huynh (NT5) và phát hiện chỉnh đồng hồ (M6) | 90 ngày | Phụ huynh sở hữu & Trẻ (`child-view`) |
| `hmac_secret_enc` | `devices` | Khóa bí mật kiểm chứng toàn vẹn Policy (mã hóa AES-256-GCM tại nơi lưu trữ) | Đến khi thu hồi thiết bị | Chỉ hệ thống Server & Agent đã ghép đôi |

### Danh mục dữ liệu TUYỆT ĐỐI KHÔNG thu thập (Cam kết chống Spyware)
1. Không lưu URL đầy đủ (đường dẫn trang con, từ khóa tìm kiếm, tham số truy vấn).
2. Không đọc tiêu đề cửa sổ, nội dung tin nhắn, email, tài liệu học tập.
3. Không ghi lại phím bấm (keylogger) hay chụp ảnh màn hình (screenshot).
4. Không truyền dữ liệu tới bất kỳ bên thứ ba nào (zero third-party telemetry).

### Cơ chế đồng ý & Xóa dữ liệu (Nghị định 13/2023/NĐ-CP)
- **Sự đồng ý của cha mẹ:** Được xác nhận rõ ràng thông qua bước phụ huynh tạo mã ghép đôi 8 ký tự (hạn 10 phút) để kích hoạt Agent.
- **Quyền xóa dữ liệu:** Nút **"Xóa toàn bộ dữ liệu của con tôi"** gọi `DELETE /api/v1/reports/{child_id}/purge`, xóa lập tức dữ liệu trên Server và gửi lệnh `PURGE_CACHE` tới mọi máy tính của trẻ.

---

## Phần 2: Phiên bản dành cho học sinh tiểu học đọc (NT1 & NT5)

> **Chào em!**
>
> **OGK** là người bạn đồng hành trên máy tính mà ba mẹ cài đặt công khai (em luôn thấy biểu tượng nhỏ ở góc dưới bên phải màn hình).
>
> - **OGK chỉ ghi nhớ 3 việc nhỏ:** Em mở ứng dụng tên gì, em vào trang web chính tên gì, và em dùng trong bao nhiêu phút — giống như một chiếc đồng hồ bấm giờ vậy!
> - **OGK KHÔNG BAO GIỜ:** đọc tin nhắn của em, chụp ảnh màn hình, hay xem em gõ gì trên bàn phím.
> - **Em luôn có tiếng nói:** Nếu hết giờ mà em đang làm dở bài tập, em có thể bấm **"Xin thêm giờ"**. Nếu trang học bị chặn nhầm, em bấm **"Em nghĩ trang này bị chặn nhầm"** để báo ba mẹ mở ngay.
> - **Minh bạch hai chiều:** Em luôn mở được màn hình **"Hôm nay em đã dùng gì"** và xem được ba mẹ đã thay đổi quy định gì vào lúc nào.
> - **An toàn là trên hết:** Tổng đài bảo vệ trẻ em **111** và các trang học tập luôn mở, không bao giờ bị khóa!
