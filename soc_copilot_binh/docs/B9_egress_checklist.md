# B9: Kiểm chứng "dữ liệu không rời hạ tầng"

Kỳ vọng: chỉ có kết nối tới localhost (Ollama :11434, Streamlit, Chroma cục bộ).

## 1. Trong tiến trình Python (nhanh, tái lập được)
```powershell
python scripts\egress_check.py            # lần 1: có thể thấy huggingface.co nếu cache chưa đủ
python scripts\egress_check.py --offline  # lần 2: kỳ vọng "Không có kết nối ra ngoài"
```
Cần Ollama đang chạy và đã pull model, nếu không luồng chưa đủ và script trả mã 2.
Script chặn và ghi lại mọi kết nối/DNS ra ngoài localhost của Python (gồm telemetry Chroma, HuggingFace, requests).
Chụp màn hình kết quả cả hai lần.

## 2. Bắt gói tin (bằng chứng độc lập, gồm cả Streamlit và trình duyệt)
- Wireshark, chọn card mạng đang dùng, display filter:
  `ip.dst != 127.0.0.0/8 && !(ip.dst==10.0.0.0/8) && !(ip.dst==192.168.0.0/16) && !dns`
  rồi chạy: Streamlit UI, phân tích vài alert, đổi model, bấm mọi nút. Kỳ vọng không có gói nào.
- Hoặc tắt hẳn mạng / rút dây, chạy cả luồng, nếu vẫn chạy đủ là đạt.
- Xem nhanh: `netstat -ano | findstr ESTABLISHED` (PowerShell) trong lúc chạy.

## 3. Các nguồn gọi ra ngoài cần kiểm tra riêng
| Nguồn | Cách kiểm tra / tắt |
|---|---|
| Chroma telemetry | đã `Settings(anonymized_telemetry=False)`; script mục 1 sẽ báo nếu còn |
| HuggingFace | `HF_HUB_OFFLINE=1` sau lần tải đầu |
| Streamlit gatherUsageStats (T9) | `.streamlit/config.toml`: `[browser]` `gatherUsageStats = false` |
| Font/CDN ngoài trong UI (T3/T9) | trình duyệt F12 → Network, lọc domain khác localhost; hoặc tìm `fonts.googleapis`, `cdn` trong code UI |

## 4. Ghi kết quả
Điền bảng: ngày, máy, lệnh, kết quả, ảnh chụp. Nếu còn kết nối ra ngoài: chặn được thì ghi cách chặn,
không thì sửa lời khẳng định trong đề cương.
