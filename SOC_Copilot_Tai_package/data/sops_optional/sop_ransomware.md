---
id: sop_ransomware
title: Xử lý ransomware (mã độc mã hoá dữ liệu)
category: Malware
default_severity: Critical
---

## Điều kiện áp dụng
Nhiều file bị đổi tên hoặc mã hoá hàng loạt, xuất hiện file ghi yêu cầu tiền chuộc, tiến trình đọc và ghi số lượng lớn file trong thời gian ngắn, cảnh báo toàn vẹn tệp dồn dập. MITRE T1486.

## Cách xác minh
Xác định máy bị ảnh hưởng, tiến trình đang mã hoá (`ps aux`, `lsof`), thời điểm bắt đầu và phạm vi thư mục hoặc chia sẻ mạng bị mã hoá.

## Ngăn chặn
Cô lập máy khỏi mạng ngay (rút cáp hoặc tắt Wi-Fi) nhưng không tắt nguồn nếu cần giữ bộ nhớ làm chứng cứ; dừng tiến trình mã hoá nếu còn chạy. Hành động đề xuất: ISOLATE_HOST, cần người xác nhận.

## Bảo toàn chứng cứ
Lưu mẫu mã độc và ghi chú đòi tiền chuộc (chỉ đọc), hash, log, chụp bộ nhớ nếu có thể.

## Triệt tiêu
Xác định và gỡ mã độc cùng cơ chế duy trì; kiểm tra các máy khác trong mạng.

## Phục hồi / Gia cố
Khôi phục từ bản sao lưu ngoại tuyến đã kiểm tra sạch; không tự ý trả tiền chuộc; đổi thông tin xác thực đã bị ảnh hưởng.

## Khi nào leo thang
Luôn báo lãnh đạo và bộ phận pháp lý; leo thang khẩn nếu lan sang nhiều máy hoặc ảnh hưởng dịch vụ quan trọng.

## Tham chiếu
NIST SP 800-61; MITRE ATT&CK T1486 (Data Encrypted for Impact).
