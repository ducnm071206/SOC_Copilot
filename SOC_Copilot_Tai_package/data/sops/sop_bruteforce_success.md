---
id: sop_bruteforce_success
title: Xử lý đăng nhập thành công sau nhiều lần thất bại (nghi chiếm tài khoản)
category: Account Compromise
default_severity: Critical
---

## Điều kiện áp dụng
Nhiều lần xác thực thất bại rồi thành công từ cùng nguồn (multiple authentication failures followed by a success). Wazuh rule 40112, level 12. Nghi tài khoản đã bị chiếm; MITRE T1110, T1078.

## Cách xác minh
Liên hệ chủ tài khoản để xác nhận. Xem lịch sử đăng nhập: `last -i <user>`, `grep Accepted /var/log/auth.log | grep <srcip>`. Xem lệnh đã chạy trong phiên (`~/.bash_history`, auditd nếu có) và so sánh IP, giờ đăng nhập với thói quen thông thường.

## Ngăn chặn
Nếu không được xác nhận hợp lệ: vô hiệu hoá tài khoản bằng `sudo usermod --expiredate 1 <user>` (`passwd -l` chỉ khoá mật khẩu, không chặn đăng nhập bằng SSH key), ngắt phiên `sudo pkill -KILL -u <user>`, chặn `<srcip>`. Hành động đề xuất: BLOCK_IP; ISOLATE_HOST (cần người xác nhận) nếu có dấu hiệu di chuyển ngang hoặc mã độc.

## Bảo toàn chứng cứ
Trước khi thay đổi gì, sao chép /var/log/auth.log, `~/.bash_history` và `~/.ssh/authorized_keys` của `<user>`, ghi `sha256sum`.

## Triệt tiêu
Tìm cơ chế duy trì truy cập: khoá lạ trong `authorized_keys`, tài khoản mới, cron (`crontab -l -u <user>`), thay đổi sudoers, tiến trình lạ (`ps aux`).

## Phục hồi / Gia cố
Đặt lại mật khẩu, thu hồi khoá SSH lạ, bật xác thực nhiều yếu tố nếu có, chỉ mở lại tài khoản khi đã kiểm tra sạch.

## Khi nào leo thang
Luôn báo trưởng ca. Leo thang khẩn nếu tài khoản có quyền sudo/root, có kết nối ra ngoài bất thường hoặc nhiều máy bị ảnh hưởng.

## Tham chiếu
NIST SP 800-61 (Containment, Eradication); MITRE ATT&CK T1110, T1078.
