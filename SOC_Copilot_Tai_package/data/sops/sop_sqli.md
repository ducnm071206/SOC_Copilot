---
id: sop_sqli
title: Xử lý tấn công SQL injection vào ứng dụng web
category: Web Attack
default_severity: High
---

## Điều kiện áp dụng
Tấn công SQL injection vào ứng dụng web (SQL injection attempt): URL hoặc tham số chứa `UNION SELECT`, `' OR 1=1`, `--`, `sleep(`. Wazuh rule 31103. MITRE T1190; OWASP A03 Injection.

## Cách xác minh
Đọc access log quanh thời điểm cảnh báo: endpoint và tham số bị nhắm tới, mã phản hồi (200 kèm kích thước lớn bất thường có thể là khai thác thành công, 4xx/5xx thường là thất bại). Kiểm tra log database xem có truy vấn bất thường không.

## Ngăn chặn
Chặn `<srcip>` ở WAF hoặc reverse proxy (Nginx: `deny <srcip>;`). Hành động đề xuất: BLOCK_IP nếu IP hợp lệ và tấn công lặp lại; REVIEW_LOG nếu chưa rõ kết quả.

## Bảo toàn chứng cứ
Lưu access log, error log, payload đầy đủ và thời điểm; ghi `sha256sum`.

## Triệt tiêu
Nếu khai thác thành công: xác định bảng và dữ liệu bị truy xuất, đổi mật khẩu và thu hồi kết nối database của ứng dụng.

## Phục hồi / Gia cố
Vá endpoint bằng truy vấn tham số hoá (Prepared Statement) hoặc ORM, cấp quyền tối thiểu cho tài khoản database của ứng dụng, bật luật WAF (ví dụ OWASP CRS).

## Khi nào leo thang
Có dấu hiệu rò rỉ dữ liệu, tài khoản database có quyền cao, hoặc phản hồi 200 khớp với payload.

## Tham chiếu
NIST SP 800-61; OWASP Top 10 A03:2021 Injection; MITRE ATT&CK T1190.
