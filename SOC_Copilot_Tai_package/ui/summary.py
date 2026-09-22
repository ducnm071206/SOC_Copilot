"""ui/summary.py: đọc/tóm tắt cảnh báo Wazuh cho giao diện (không gọi LLM, không phụ thuộc code của Bình).

Bản tóm tắt này chỉ để analyst xác nhận "đầu vào có đúng không" TRƯỚC khi chạy phân tích. Việc chuẩn hoá thật
(normalize_alert, extract_src_ip...) do soc_copilot/features.py của Bình đảm nhiệm.
"""
from __future__ import annotations

import json
from typing import Any, Optional

from .safe import strip_ctrl, truncate

PRIORITY_BY_SEVERITY = {"Critical": "P1", "High": "P2", "Medium": "P3", "Low": "P4"}


def default_priority(severity: Any) -> str:
    return PRIORITY_BY_SEVERITY.get(severity if isinstance(severity, str) else "", "P3")


def unwrap(alert: Any) -> dict:
    """Bóc `_source` nếu analyst copy từ Discover của Wazuh dashboard."""
    if isinstance(alert, dict) and isinstance(alert.get("_source"), dict):
        return alert["_source"]
    return alert if isinstance(alert, dict) else {}


def _g(obj: Any, *keys: str, default: Any = None) -> Any:
    cur = obj
    for k in keys:
        if isinstance(cur, dict) and k in cur:
            cur = cur[k]
        else:
            return default
    return cur


def _txt(v: Any, limit: int = 300) -> str:
    if v is None:
        return ""
    if isinstance(v, (list, tuple)):
        v = ", ".join(str(x) for x in v)
    elif isinstance(v, dict):
        v = json.dumps(v, ensure_ascii=False)
    return strip_ctrl(v)[:limit]


# ----------------------------------------------------------------------------- đọc JSON
def parse_alert_text(text: str, max_alerts: int = 500) -> tuple[list[dict], Optional[str]]:
    """Trả về (danh sách cảnh báo, thông báo lỗi). Chấp nhận: 1 object, mảng, JSON Lines, kết quả OpenSearch (hits.hits)."""
    t = (text or "").strip()
    if not t:
        return [], None
    try:
        obj: Any = json.loads(t)
    except json.JSONDecodeError as e:
        lines = t.splitlines()
        first_ok = False
        if len([ln for ln in lines if ln.strip()]) > 1:
            try:
                json.loads(next(ln for ln in lines if ln.strip()))
                first_ok = True
            except (json.JSONDecodeError, StopIteration):
                pass
        if not first_ok:
            return [], f"JSON không hợp lệ ở dòng {e.lineno}, cột {e.colno}: {e.msg}"
        obj = []
        for n, ln in enumerate(lines, 1):
            if not ln.strip():
                continue
            try:
                obj.append(json.loads(ln))
            except json.JSONDecodeError as e2:
                return [], f"JSON Lines không hợp lệ ở dòng {n}, cột {e2.colno}: {e2.msg}"
    items = obj
    if isinstance(obj, dict):
        hits = _g(obj, "hits", "hits")
        items = hits if isinstance(hits, list) else [obj]
    elif not isinstance(obj, list):
        return [], "Nội dung phải là một đối tượng JSON (hoặc danh sách các đối tượng)."
    out: list[dict] = []
    for i, it in enumerate(items[:max_alerts], 1):
        if not isinstance(it, dict):
            return [], f"Phần tử thứ {i} không phải đối tượng JSON."
        out.append(it)
    return out, None


def validate_alert(alert: Any) -> Optional[str]:
    a = unwrap(alert)
    if not isinstance(a.get("rule"), dict) or _g(a, "rule", "id") in (None, ""):
        return "Thiếu trường rule.id: đây không giống một cảnh báo Wazuh hợp lệ."
    return None


# ----------------------------------------------------------------------------- tóm tắt
def summarize(alert: Any) -> list[tuple[str, str]]:
    """Danh sách (nhãn, giá trị) dạng văn bản thuần để hiển thị bằng st.dataframe/st.table."""
    a = unwrap(alert)
    srcip = _txt(_g(a, "data", "srcip"))
    if srcip in ("", "?"):
        srcip = "(không có trong data.srcip)"
    mitre = _g(a, "rule", "mitre", "id") or _g(a, "rule", "mitre", "technique")
    return [
        ("Rule", f"{_txt(_g(a, 'rule', 'id'), 40)} (level {_txt(_g(a, 'rule', 'level'), 10)})"),
        ("Mô tả", _txt(_g(a, "rule", "description"))),
        ("Nhóm (groups)", _txt(_g(a, "rule", "groups"))),
        ("Agent", _txt(_g(a, "agent", "name"))),
        ("IP nguồn (srcip)", srcip),
        ("MITRE", _txt(mitre) or "(không có)"),
        ("Thời gian", _txt(a.get("timestamp") or a.get("@timestamp"))),
        ("Nguồn log (location)", _txt(a.get("location"))),
    ]


def evidence(alert: Any) -> list[tuple[str, str]]:
    """Các bằng chứng thô (nhãn tĩnh, nội dung động) để hiển thị bằng st.code."""
    a = unwrap(alert)
    out: list[tuple[str, str]] = []
    for label, val in (
        ("URL (data.url)", _g(a, "data", "url")),
        ("Đường dẫn tệp (syscheck.path)", _g(a, "syscheck", "path")),
        ("Người dùng nguồn (data.srcuser)", _g(a, "data", "srcuser")),
        ("Người dùng đích (data.dstuser)", _g(a, "data", "dstuser")),
        ("Log gốc (full_log)", a.get("full_log")),
    ):
        text = _txt(val, 100000)
        if text:
            out.append((label, truncate(text, 3000)))
    return out


def alert_label(alert: Any, i: int) -> str:
    a = unwrap(alert)
    return f"#{i + 1}  rule {_txt(_g(a, 'rule', 'id'), 20)}  {_txt(_g(a, 'rule', 'description'), 60)}"
