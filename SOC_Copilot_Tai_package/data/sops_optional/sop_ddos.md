---
id: sop_ddos
title: Xử lý tấn công từ chối dịch vụ (DoS/DDoS)
category: Availability
default_severity: High
---

## Điều kiện áp dụng
Lưu lượng hoặc số request tăng đột biến làm suy giảm dịch vụ (flooding, DoS, DDoS). Dấu hiệu: CPU, băng thông hoặc số kết nối tăng vọt, nhiều request từ một hoặc nhiều nguồn. MITRE T1498, T1499.

## Cách xác minh
Xác định loại lưu lượng (HTTP, SYN, UDP), tốc độ request và nguồn: một IP (DoS) hay phân tán (DDoS). Dùng `ss -s`, `netstat -an | grep SYN_RECV | wc -l`, access log.

## Ngăn chặn
Bật giới hạn tốc độ (ví dụ Nginx `limit_req`), chặn IP hoặc dải nguồn tại firewall; nếu quy mô lớn, nhờ nhà cung cấp hạ tầng hoặc CDN lọc lưu lượng. Hành động đề xuất: BLOCK_IP khi nguồn là một IP; REVIEW_LOG khi phân tán.

## Bảo toàn chứng cứ
Lưu mẫu gói tin ngắn (`tcpdump -c 1000 -w sample.pcap`) và log của khoảng thời gian tấn công.

## Triệt tiêu
Không có mã độc cần gỡ; kiểm tra máy có bị lợi dụng làm nguồn tấn công không.

## Phục hồi / Gia cố
Bật SYN cookies, rate limiting, autoscaling hoặc CDN; xây dựng kế hoạch chịu tải.

## Khi nào leo thang
Dịch vụ quan trọng ngừng hoạt động, tấn công vượt khả năng tự xử lý, hoặc có yêu cầu tống tiền đi kèm.

## Tham chiếu
NIST SP 800-61; MITRE ATT&CK T1498, T1499.
