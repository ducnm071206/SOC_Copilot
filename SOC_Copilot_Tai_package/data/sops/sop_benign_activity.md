---
id: sop_benign_activity
title: Hoạt động hệ thống bình thường (không cần xử lý)
category: Benign
default_severity: Low
---

## Điều kiện áp dụng
Cảnh báo mức thấp phản ánh hoạt động bình thường: sudo thành công (successful sudo to ROOT), lần đầu user dùng sudo (first time user executed sudo), phiên đăng nhập mở hoặc đóng (PAM login session opened, closed), đăng nhập SSH thành công (sshd authentication success), Wazuh server khởi động (server started), xoay vòng log (log file rotated). Wazuh rule 5402, 5403, 5501, 5502, 5715, 502, 591.

## Cách xác minh
Đối chiếu người dùng, máy, IP nguồn và giờ với hoạt động dự kiến (lịch trực, bảo trì, quản trị viên). Lành tính khi tài khoản, IP và thời điểm đều hợp lệ.

## Ngăn chặn
Không cần ngăn chặn. Hành động đề xuất: NO_ACTION; chỉ ghi nhận vào lịch sử.

## Bảo toàn chứng cứ
Không cần bảo toàn đặc biệt; giữ bản ghi cảnh báo theo chính sách lưu log.

## Triệt tiêu
Không áp dụng.

## Phục hồi / Gia cố
Không áp dụng. Có thể tinh chỉnh luật để giảm nhiễu nếu cảnh báo lặp lại nhiều.

## Khi nào leo thang
Chuyển sang SOP khác nếu tài khoản không được phép dùng sudo, IP nguồn lạ, giờ bất thường, hoặc lặp lại bất thường (xem SOP nâng quyền hoặc đăng nhập thành công sau nhiều lần thất bại).

## Tham chiếu
NIST SP 800-61 (giai đoạn phát hiện và phân tích).
