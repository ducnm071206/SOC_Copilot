---
id: sop_web_attack_generic
title: Xử lý tấn công web chung (đã phản hồi 200 hoặc lặp lại)
category: Web Attack
default_severity: Medium
---

## Điều kiện áp dụng
Tấn công web chưa rõ loại: common web attack, web attack returned code 200 (success), nhiều tấn công web lặp lại từ cùng IP. Wazuh rule 31104, 31106, 31153. Chưa xác định là SQLi, XSS hay RCE. MITRE T1190.

## Cách xác minh
Đọc request và phản hồi: kích thước, nội dung có khác trang bình thường không; endpoint có tồn tại và xử lý tham số không; ứng dụng có ghi lỗi cùng thời điểm không. Nếu khớp SQLi, XSS hoặc RCE thì chuyển SOP tương ứng.

## Ngăn chặn
Dò quét không thành công: theo dõi, REVIEW_LOG. Tấn công lặp lại từ IP ngoài: BLOCK_IP ở WAF hoặc reverse proxy.

## Bảo toàn chứng cứ
Lưu access log và request đầy đủ.

## Triệt tiêu
Nếu khai thác thành công: làm theo SOP của loại tấn công đó; vô hiệu hoá hoặc vá endpoint bị lạm dụng.

## Phục hồi / Gia cố
Kiểm tra và làm sạch đầu vào, bật WAF, cập nhật ứng dụng.

## Khi nào leo thang
Xác nhận có khai thác thành công, hoặc cùng IP xuất hiện trong nhiều cảnh báo mức cao.

## Tham chiếu
NIST SP 800-61; MITRE ATT&CK T1190.
