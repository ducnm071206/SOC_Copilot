"""ui/ticket.py: dựng nội dung "ticket" để tải xuống (T6). Không gửi đi đâu, không gọi hệ thống ngoài."""
from __future__ import annotations

import json
import re
from typing import Any, Optional

from .safe import md_escape, md_text, sanitize_markdown, valid_ip
from .summary import evidence, unwrap

NOTE = ("Ticket này được xuất từ SOC Analyst Copilot. Hệ thống KHÔNG thực thi bất kỳ hành động nào "
        "(chặn IP, cô lập máy...). Đề xuất do mô hình và luật kiểm tra tạo ra; người phân tích quyết định cuối cùng.")


_SEV = ("Low", "Medium", "High", "Critical")


def code(x: Any, limit: int = 120) -> str:
    """Giá trị ngắn (ID, IP, hành động) dạng code span; bỏ ký tự ` và xuống dòng để không thoát khỏi span."""
    s = re.sub(r"\s+", " ", str(x if x is not None else "")).replace("`", "'").strip()[:limit]
    return f"`{s}`" if s else "(không có)"


def _fence(text: str) -> str:
    """Dấu rào code đủ dài để nội dung log chứa ``` cũng không thoát khỏi khối code."""
    longest = max((len(m) for m in re.findall(r"`+", text)), default=0)
    return "`" * max(3, longest + 1)


def _block(text: str) -> str:
    f = _fence(text)
    return f"{f}\n{text}\n{f}"


def build_ticket_markdown(rec_id: Any, res: dict, alert: Any, priority: Optional[str],
                          status: Optional[str], created_ts: Optional[str] = None) -> str:
    a = unwrap(alert)
    rule_id = (a.get("rule") or {}).get("id", "?") if isinstance(a.get("rule"), dict) else "?"
    ip = res.get("action_target_ip") or (res.get("alert_summary") or {}).get("srcip") or ""
    sev = res.get("severity") if res.get("severity") in _SEV else "?"
    prio = priority if priority in ("P1", "P2", "P3", "P4") else "P3"
    title = f"[{prio}][{sev}] " + md_escape(res.get("attack_type") or "Chưa phân loại", 150) + " - rule " + md_escape(rule_id, 20)
    if ip:
        title += " - " + (valid_ip(ip) or md_escape(ip, 64))
    out = [f"# {title}", "",
           f"- Mã bản ghi: {code(rec_id)}",
           f"- Thời điểm phân tích: {code(created_ts)}",
           f"- Trạng thái: {code(status)}",
           f"- Ưu tiên: {code(priority)}",
           f"- Mức nghiêm trọng (LLM / theo rule.level): {code(res.get('severity'))} / {code(res.get('rule_severity'))}",
           "", "## Tóm tắt", md_text(res.get("summary") or "", 2000), "", "## Bằng chứng"]
    ev = evidence(alert)
    if not ev:
        out.append("(không có)")
    for label, text in ev:
        out += [f"### {label}", _block(text), ""]
    out += ["## SOP áp dụng",
            f"- SOP: {code(res.get('sop_id'))}",
            f"- Khoảng cách truy xuất: {code(res.get('sop_distance'))} (dùng fallback: {'có' if res.get('sop_is_fallback') else 'không'})",
            "", "## Hành động đề xuất",
            f"- {code(res.get('recommended_action'))}" + (f" -> {code(ip)}" if res.get('recommended_action') == 'BLOCK_IP' and ip else ""),
            f"- Cần người xác nhận: {'có' if res.get('needs_human_confirm') else 'không'}"]
    for n in res.get("guard_notes") or []:
        out.append(f"- Ghi chú kiểm tra: {md_escape(n, 500)}")
    if res.get("suspected_injection"):
        out.append("- CẢNH BÁO: nghi ngờ nội dung alert chứa lời chèn lệnh (prompt injection).")
    out += ["", "## Báo cáo phân tích (do mô hình sinh)", sanitize_markdown(res.get("report_md") or "(không có)"), "",
            "## Ghi chú", NOTE, ""]
    return "\n".join(out)


def build_ticket_json(rec_id: Any, res: dict, alert: Any, priority: Optional[str],
                      status: Optional[str], created_ts: Optional[str] = None) -> str:
    return json.dumps({"id": rec_id, "created": created_ts, "status": status, "priority": priority,
                       "alert": alert, "result": res, "note": NOTE}, ensure_ascii=False, indent=2, default=str)
