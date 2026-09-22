---
id: sop_web_bruteforce_scan
title: Xử lý dò quét web tự động (scanner, nhiều lỗi 4xx)
category: Reconnaissance
default_severity: Medium
---

## Điều kiện áp dụng
Dò quét web tự động: nhiều lỗi 400/404/403/501 từ cùng IP (web server 400 error code, multiple 400 error codes from same source), truy cập đường dẫn nhạy cảm như `/admin`, `/.git`, file `.inc`, `/scripts`. Wazuh rule 31101, 31121, 31151, 30305, 31516. MITRE T1595.002.

## Cách xác minh
Đếm số request lỗi từ `<srcip>` trong access log, xem User-Agent (nikto, sqlmap, curl) và các đường dẫn bị dò. Tìm request nào trả 200 hoặc 302 tới đường dẫn nhạy cảm để điều tra sâu.

## Ngăn chặn
Nếu quét liên tục: chặn tạm `<srcip>` ở WAF hoặc reverse proxy, hoặc giới hạn tốc độ; không chặn nếu IP là proxy hoặc CDN dùng chung. Hành động đề xuất: REVIEW_LOG khi lẻ tẻ; BLOCK_IP khi liên tục từ IP ngoài.

## Bảo toàn chứng cứ
Lưu đoạn access log của phiên quét.

## Triệt tiêu
Không có mã độc; đảm bảo không lộ file nhạy cảm (backup, `.git`, file cấu hình).

## Phục hồi / Gia cố
Bật rate limiting, ẩn thông tin phiên bản, xoá file thừa, thêm luật fail2ban cho nhiều lỗi 4xx.

## Khi nào leo thang
Có request 200 hoặc 302 vào đường dẫn nhạy cảm, hoặc cùng IP sau đó xuất hiện trong cảnh báo SQLi, XSS hoặc RCE.

## Tham chiếu
NIST SP 800-61; MITRE ATT&CK T1595.002 (Vulnerability Scanning).
