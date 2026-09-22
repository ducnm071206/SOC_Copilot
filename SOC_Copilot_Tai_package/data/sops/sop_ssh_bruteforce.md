---
id: sop_ssh_bruteforce
title: Xử lý SSH brute force (đăng nhập SSH thất bại liên tục)
category: Brute Force
default_severity: High
---

## Điều kiện áp dụng
Nhiều lần đăng nhập SSH thất bại từ một IP trong thời gian ngắn (sshd authentication failed, brute force, attempt to login using a non-existent user, maximum authentication attempts exceeded, PAM multiple failed logins). Wazuh rule 5710, 5712, 5758, 5760, 5503, 5551, 2502; MITRE T1110. Chưa có đăng nhập thành công.

## Cách xác minh
Đếm số lần thất bại và số user bị thử: `grep 'Failed password' /var/log/auth.log | grep <srcip> | wc -l` (RHEL: /var/log/secure). Kiểm tra `<srcip>` có thuộc mạng nội bộ, IP quản trị hoặc máy giám sát hợp lệ không. Tìm đăng nhập thành công từ cùng IP: `grep Accepted /var/log/auth.log | grep <srcip>`.

## Ngăn chặn
Nếu là IP ngoài và không thuộc allowlist: chặn `sudo iptables -I INPUT -s <srcip> -j DROP` hoặc dùng active-response firewall-drop của Wazuh, đặt thời hạn chặn. Hành động đề xuất: BLOCK_IP; chuyển REVIEW_LOG nếu IP nội bộ hoặc không rõ.

## Bảo toàn chứng cứ
Sao chép log xác thực và bản ghi cảnh báo Wazuh liên quan sang thư mục chứng cứ, ghi `sha256sum` trước khi log bị xoay vòng.

## Triệt tiêu
Không có mã độc cần gỡ. Rà soát tài khoản dùng mật khẩu yếu hoặc mật khẩu mặc định.

## Phục hồi / Gia cố
Đặt `PasswordAuthentication no` và `PermitRootLogin no` trong sshd_config, dùng SSH key, `MaxAuthTries 3`, giới hạn SSH theo IP hoặc VPN, cài fail2ban.

## Khi nào leo thang
Có đăng nhập thành công sau chuỗi thất bại (chuyển sang sop_bruteforce_success), nguồn phân tán nhiều IP, hoặc mục tiêu là tài khoản đặc quyền.

## Tham chiếu
NIST SP 800-61 (pha Containment); MITRE ATT&CK T1110.
