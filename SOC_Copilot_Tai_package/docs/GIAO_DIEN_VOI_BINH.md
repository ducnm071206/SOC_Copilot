# Hợp đồng giao diện giữa dashboard (Tài) và lõi pipeline (Bình)

Giao diện chỉ gọi qua `ui/backend.py`. Khi `soc_copilot.core` nạp được thì UI tự dùng bản thật (banner "MÔ PHỎNG" biến mất).

## Hàm Bình cần cung cấp
- `soc_copilot.core.analyze_alert(alert, model=..., threshold=..., retrieval=...)` trả `AnalysisResult` (pydantic) hoặc dict. Không ném exception ra ngoài; lỗi ghi vào `ok=False`, `error`.
- `soc_copilot.llm.health()` trả dict `{ok: bool, version: str|None, models: list[str], error: str|None}` (models là tên model đã pull).
- `soc_copilot.config`: `THRESHOLD`, `DEFAULT_MODEL`, `PROTECTED_IPS` (list IP/CIDR), `DB_PATH` (tuỳ chọn; storage.py dùng nếu có, không thì dùng biến môi trường `SOC_COPILOT_DB` hoặc `soc_copilot.db`).
- `soc_copilot/__init__.py` phải nhẹ (không import chromadb/sentence-transformers ở mức module) vì `storage.py` nằm trong cùng package.

## Trường của kết quả mà UI đọc (thiếu trường nào UI vẫn chạy, chỉ không hiển thị mục đó)
`ok, error, alert_summary{rule_id, level, srcip}, attack_type, summary, severity, rule_severity, severity_mismatch, recommended_action (BLOCK_IP, ISOLATE_HOST, REVIEW_LOG, NO_ACTION), action_target_ip, needs_human_confirm, sop_id, sop_distance, sop_is_fallback, sop_alternatives[{sop_id, distance}], report_md, guard_notes[], suspected_injection, truncated, timings{t_retrieve, t_llm, t_total}, meta{model, prompt_version, retrieval_mode}`

## Ba chế độ truy xuất (giá trị của `retrieval`)
`rag`, `rule_map` (đọc `data/rule_map.yaml`), `full_context`.

## Lưu ý về kho SOP
- Mỗi SOP dài 1.100 đến 1.700 ký tự. Chế độ `full_context` với 13 SOP khoảng 17.000 ký tự, cần `num_ctx` từ 8192 trở lên, hoặc chỉ đưa phần "Điều kiện áp dụng" của mọi SOP vào prompt.
- Mô hình embedding đa ngôn ngữ kiểu MiniLM chỉ đọc khoảng 128 token đầu. Nên embed `title + category + mục "Điều kiện áp dụng"` thay vì cả file; mục này đã được đặt ở đầu và có sẵn mô tả tiếng Anh của cảnh báo Wazuh.
- `data/sops_optional/` (DDoS, ransomware) chưa được nạp; chuyển vào `data/sops/` nếu nhóm muốn thêm SOP gây nhiễu.
