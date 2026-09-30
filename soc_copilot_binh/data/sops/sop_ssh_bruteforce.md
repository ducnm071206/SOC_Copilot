---
id: sop_ssh_bruteforce
title: SSH Brute Force
category: authentication
default_severity: High
---
Áp dụng khi có nhiều lần đăng nhập SSH thất bại từ cùng một IP (rule sshd, authentication_failed).
1. Đếm số lần thất bại và các tài khoản bị thử (root, admin, user không tồn tại).
2. Kiểm tra IP nguồn có nằm trong danh sách tin cậy không.
3. Nếu có đăng nhập thành công sau chuỗi thất bại, coi là nghi xâm nhập: khoá tài khoản và báo trưởng nhóm.
4. Nếu chỉ có thất bại, chặn IP nguồn trên firewall.
5. Khuyến nghị tắt đăng nhập bằng mật khẩu, dùng khoá SSH.
