---
id: sop_general
title: Quy trình chung cho cảnh báo chưa có SOP phù hợp
category: General
default_severity: Medium
---

## Điều kiện áp dụng
Dùng khi không có SOP nào khớp với cảnh báo (khoảng cách truy xuất vượt ngưỡng) hoặc loại cảnh báo chưa được hỗ trợ. General security incident, alert chưa phân loại.

## Cách xác minh
Đọc rule (id, mô tả, level), agent, thời điểm, nguồn và đích. Tìm cảnh báo khác cùng `<srcip>` hoặc cùng agent trong khoảng ±1 giờ. Đánh giá sơ bộ: hoạt động bình thường, cấu hình sai hay có dấu hiệu tấn công.

## Ngăn chặn
Chưa đủ căn cứ thì không chặn IP và không cô lập máy. Hành động đề xuất: REVIEW_LOG để analyst xem xét; NO_ACTION chỉ khi rõ ràng lành tính và level thấp.

## Bảo toàn chứng cứ
Lưu bản ghi cảnh báo gốc và log liên quan.

## Triệt tiêu
Chưa áp dụng cho đến khi xác định được loại sự cố.

## Phục hồi / Gia cố
Ghi nhận trường hợp và đề xuất bổ sung SOP cho loại cảnh báo này.

## Khi nào leo thang
Level của rule từ 12 trở lên, nhiều cảnh báo lạ cùng nguồn, hoặc ảnh hưởng tới máy chủ quan trọng.

## Tham chiếu
NIST SP 800-61 (giai đoạn phát hiện và phân tích).
