---
id: sop_web_rce
title: Xử lý thực thi mã từ xa qua web (Shellshock, command injection)
category: Remote Code Execution
default_severity: Critical
---

## Điều kiện áp dụng
Thực thi mã từ xa qua web: Shellshock (chuỗi `() { :;};` trong header User-Agent, Cookie hoặc Referer, CVE-2014-6271), command injection. Wazuh rule 31166, 31168, level 15. MITRE T1190, T1059.

## Cách xác minh
Xác định URL CGI và header chứa payload; xem phản hồi có cho thấy lệnh đã chạy không. Kiểm tra máy chủ có bật CGI và bash chưa vá: `env x='() { :;}; echo vulnerable' bash -c 'echo test'` (in ra 'vulnerable' là còn lỗi). Tìm kết nối ra ngoài bất thường `ss -tunp` và tiến trình lạ `ps aux --forest`.

## Ngăn chặn
Chặn `<srcip>`. Hành động đề xuất: BLOCK_IP; nếu thấy lệnh đã chạy (tiến trình con của web server, kết nối ra ngoài) thì ISOLATE_HOST, cần người xác nhận.

## Bảo toàn chứng cứ
Lưu access log, danh sách tiến trình và kết nối (`ps aux`, `ss -tunp`), ghi `sha256sum`; chụp bộ nhớ nếu có công cụ, trước khi khởi động lại dịch vụ.

## Triệt tiêu
Tắt CGI không cần thiết. Nếu đã bị khai thác: tìm web shell, cron, tài khoản mới, file lạ trong /tmp và thư mục web, dừng tiến trình lạ.

## Phục hồi / Gia cố
Cập nhật bash (`sudo apt install --only-upgrade bash` hoặc `sudo yum update bash`), khôi phục từ bản sạch nếu nghi bị chiếm quyền điều khiển.

## Khi nào leo thang
Luôn báo trưởng ca vì rule level 15. Leo thang khẩn nếu lệnh chạy thành công hoặc có kết nối ra ngoài.

## Tham chiếu
NIST SP 800-61; MITRE ATT&CK T1190, T1059; CVE-2014-6271.
