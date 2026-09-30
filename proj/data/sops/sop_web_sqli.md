---
id: sop_web_sqli
title: SQL Injection Attempt
category: web_attack
default_severity: High
---
Áp dụng khi log web chứa payload SQL (UNION SELECT, OR 1=1, dấu nháy và comment).
1. Xem URL và tham số bị tấn công, mã phản hồi HTTP (200 có thể là dấu hiệu thành công).
2. Kiểm tra log ứng dụng và cơ sở dữ liệu cùng thời điểm để tìm truy vấn bất thường.
3. Chặn IP nguồn nếu tấn công lặp lại từ ngoài mạng nội bộ.
4. Báo nhóm phát triển rà soát đoạn code xử lý tham số đó (dùng prepared statement).
