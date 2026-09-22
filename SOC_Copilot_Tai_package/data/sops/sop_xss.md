---
id: sop_xss
title: Xử lý tấn công Cross-Site Scripting (XSS)
category: Web Attack
default_severity: Medium
---

## Điều kiện áp dụng
Tấn công XSS (cross site scripting attempt): URL hoặc tham số chứa `<script>`, `onerror=`, `javascript:`. Wazuh rule 31105; rule 31154 khi lặp lại nhiều lần từ cùng IP. OWASP A03.

## Cách xác minh
Xác định payload, endpoint và loại XSS: reflected (payload chỉ nằm trong request và phản hồi) hay stored (đã lưu vào dữ liệu). Kiểm tra mã phản hồi và xem payload có được in nguyên văn trong HTML không.

## Ngăn chặn
Chặn `<srcip>` nếu tấn công lặp lại. Hành động đề xuất: REVIEW_LOG khi chưa xác nhận khai thác; BLOCK_IP khi tấn công liên tục từ IP ngoài.

## Bảo toàn chứng cứ
Lưu request và response chứa payload, access log.

## Triệt tiêu
Nếu là stored XSS: sao lưu rồi xoá bản ghi chứa payload trong database.

## Phục hồi / Gia cố
Escape đầu ra theo ngữ cảnh (HTML, JS, URL), thêm Content-Security-Policy, đặt cờ HttpOnly và Secure cho cookie phiên.

## Khi nào leo thang
Payload đã lưu trong trang mà người dùng khác xem, hoặc có dấu hiệu bị đánh cắp phiên (cookie).

## Tham chiếu
NIST SP 800-61; OWASP Top 10 A03:2021 Injection.
