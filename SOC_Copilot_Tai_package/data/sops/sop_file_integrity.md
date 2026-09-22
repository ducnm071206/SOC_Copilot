---
id: sop_file_integrity
title: Xử lý cảnh báo toàn vẹn tệp (File Integrity Monitoring)
category: File Integrity
default_severity: Medium
---

## Điều kiện áp dụng
Wazuh syscheck báo tệp bị thay đổi, thêm hoặc xoá (integrity checksum changed, file added to the system, file deleted). Wazuh rule 550, 553, 554. Đáng ngờ khi đường dẫn nằm trong thư mục web, /etc, /bin, /usr/bin, cron hoặc `.ssh`. MITRE T1565, T1505.003.

## Cách xác minh
Xác định `<path>`, chủ sở hữu, thời điểm và người dùng hay tiến trình đã thay đổi (`stat <path>`, `ausearch -f <path>` nếu có auditd). Đối chiếu lịch bảo trì, cập nhật gói (`debsums`, `rpm -V`) hoặc triển khai hợp lệ; thay đổi do cập nhật gói hoặc cấu hình dịch vụ hệ thống thường lành tính.

## Ngăn chặn
Nghi web shell hoặc mã độc: ISOLATE_HOST (cần người xác nhận) và dừng tiến trình liên quan. Lành tính: NO_ACTION và ghi nhận. Chưa rõ: REVIEW_LOG.

## Bảo toàn chứng cứ
Trước khi xoá hoặc sửa: `sha256sum <path>`, `stat <path>`, sao chép nguyên trạng `cp -p <path> /evidence/` (đặt chỉ đọc).

## Triệt tiêu
Sau khi lưu chứng cứ, chuyển file độc hại vào thư mục cách ly thay vì xoá vội, gỡ cron hoặc cơ chế duy trì liên quan.

## Phục hồi / Gia cố
Khôi phục file từ bản sạch hoặc gói gốc, đặt web root ở chế độ chỉ đọc, tinh chỉnh danh sách thư mục syscheck để giảm nhiễu.

## Khi nào leo thang
Có file thực thi hoặc script lạ trong thư mục web; thay đổi /etc/passwd, /etc/shadow, sudoers hoặc `authorized_keys`.

## Tham chiếu
NIST SP 800-61 (bảo toàn chứng cứ); MITRE ATT&CK T1505.003 (Web Shell), T1565.
