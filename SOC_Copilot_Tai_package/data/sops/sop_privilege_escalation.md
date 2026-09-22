---
id: sop_privilege_escalation
title: Xử lý nâng quyền trái phép (privilege escalation)
category: Privilege Escalation
default_severity: High
---

## Điều kiện áp dụng
Nỗ lực hoặc hành vi nâng quyền: `su` thất bại nhiều lần (user missed the password to change UID to root), sudo bất thường, thêm user vào nhóm sudo hoặc wheel, xuất hiện tệp SUID mới. Wazuh rule 5301. MITRE T1548, T1068.

## Cách xác minh
Xác định tài khoản, thời điểm, lệnh và việc có được phê duyệt không: `grep -E 'su:|sudo' /var/log/auth.log`. Kiểm tra nhóm đặc quyền `getent group sudo wheel` và tệp SUID mới `find / -xdev -perm -4000 -type f -mtime -1`.

## Ngăn chặn
Nếu trái phép: vô hiệu hoá tài khoản `sudo usermod --expiredate 1 <user>`, ngắt phiên `sudo pkill -KILL -u <user>`, gỡ quyền `sudo gpasswd -d <user> sudo`. Nghi khai thác lỗ hổng nhân: ISOLATE_HOST, cần người xác nhận. Nếu chỉ là nhập sai mật khẩu đơn lẻ: REVIEW_LOG.

## Bảo toàn chứng cứ
Sao chép auth.log, danh sách nhóm và danh sách tệp SUID, ghi `sha256sum`, trước khi thay đổi.

## Triệt tiêu
Rà soát mọi hành động của tài khoản trong phiên; gỡ backdoor, tài khoản hoặc khoá SSH mới thêm.

## Phục hồi / Gia cố
Đặt lại thông tin xác thực, áp dụng đặc quyền tối thiểu, cập nhật nhân và các gói có lỗ hổng.

## Khi nào leo thang
Tài khoản đã đạt quyền root, hoặc có tiến trình chạy quyền root do người dùng thường khởi tạo.

## Tham chiếu
NIST SP 800-61; MITRE ATT&CK T1548, T1068.
