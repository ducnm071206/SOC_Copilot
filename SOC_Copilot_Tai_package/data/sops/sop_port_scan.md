---
id: sop_port_scan
title: Xử lý quét cổng (port scan)
category: Reconnaissance
default_severity: Medium
---

## Điều kiện áp dụng
Quét cổng: một IP thử kết nối tới nhiều cổng hoặc nhiều địa chỉ trong thời gian ngắn, log firewall ghi nhiều kết nối bị chặn, dấu hiệu công cụ như Nmap. MITRE T1046, T1595.

## Cách xác minh
Xác định `<srcip>`, số cổng, tốc độ và thời gian từ log firewall (`iptables -L -v -n`, log UFW hoặc nftables). Phân biệt với công cụ giám sát hoặc quét lỗ hổng nội bộ được cấp phép.

## Ngăn chặn
IP ngoài quét liên tục: chặn `<srcip>`. Hành động đề xuất: BLOCK_IP. IP nội bộ của đội quản trị: NO_ACTION và ghi nhận. Chưa rõ: REVIEW_LOG.

## Bảo toàn chứng cứ
Lưu log firewall của khoảng thời gian quét.

## Triệt tiêu
Không có mã độc; xác định cổng nào đã phản hồi (mở) với IP này.

## Phục hồi / Gia cố
Đóng cổng dịch vụ không cần thiết (liệt kê bằng `ss -tulpn`), giới hạn theo IP, bật giới hạn tốc độ kết nối.

## Khi nào leo thang
Sau quét có cảnh báo tấn công vào dịch vụ vừa bị lộ cổng, hoặc quét xuất phát từ máy nội bộ.

## Tham chiếu
NIST SP 800-61; MITRE ATT&CK T1046, T1595.
