"""ui/mock_backend.py: backend GIẢ để phát triển giao diện khi chưa có soc_copilot của Bình.

KHÔNG dùng số liệu của file này trong báo cáo. Kết quả được đánh dấu meta.model = "MOCK".
Chọn SOP bằng data/rule_map.yaml, lấy nội dung "Cách xác minh"/"Ngăn chặn" từ data/sops/*.md để demo luồng UI.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .safe import valid_ip
from .summary import unwrap

ROOT = Path(__file__).resolve().parents[1]
SOP_DIR = ROOT / "data" / "sops"
RULE_MAP = ROOT / "data" / "rule_map.yaml"

ACTION_BY_SOP = {
    "sop_ssh_bruteforce": "BLOCK_IP", "sop_bruteforce_success": "BLOCK_IP", "sop_sqli": "BLOCK_IP",
    "sop_web_rce": "BLOCK_IP", "sop_xss": "REVIEW_LOG", "sop_web_attack_generic": "REVIEW_LOG",
    "sop_web_bruteforce_scan": "REVIEW_LOG", "sop_file_integrity": "REVIEW_LOG",
    "sop_privilege_escalation": "REVIEW_LOG", "sop_benign_activity": "NO_ACTION", "sop_general": "REVIEW_LOG",
}
ATTACK_BY_SOP = {
    "sop_ssh_bruteforce": "SSH brute force", "sop_bruteforce_success": "Nghi chiếm tài khoản (brute force thành công)",
    "sop_sqli": "SQL injection", "sop_xss": "Cross-site scripting", "sop_web_rce": "Thực thi mã từ xa (Shellshock)",
    "sop_web_attack_generic": "Tấn công web chung", "sop_web_bruteforce_scan": "Dò quét web",
    "sop_file_integrity": "Thay đổi toàn vẹn tệp", "sop_privilege_escalation": "Nâng quyền",
    "sop_benign_activity": "Hoạt động bình thường", "sop_general": "Chưa phân loại",
}
_INJECTION = re.compile(r"ignore\s+(all\s+)?(previous|prior)|system\s*:|recommended_action|bỏ qua (mọi )?hướng dẫn", re.I)


def level_bucket(level: Any) -> str:
    try:
        lv = int(level)
    except (TypeError, ValueError):
        return "Medium"
    return "Low" if lv <= 4 else "Medium" if lv <= 7 else "High" if lv <= 11 else "Critical"


def _rule_map() -> tuple[dict, str]:
    try:
        import yaml
        d = yaml.safe_load(RULE_MAP.read_text(encoding="utf8")) or {}
        return {str(k): v for k, v in (d.get("rules") or {}).items()}, d.get("default", "sop_general")
    except Exception:
        return {}, "sop_general"


def _sop_section(sid: str, heading: str) -> str:
    try:
        text = (SOP_DIR / f"{sid}.md").read_text(encoding="utf8")
    except OSError:
        return ""
    m = re.search(rf"^## {re.escape(heading)}\s*\n(.*?)(?=^## |\Z)", text, re.S | re.M)
    return m.group(1).strip() if m else ""


def health() -> dict:
    return {"ok": True, "version": "mock", "models": ["mock-model"], "error": None}


def analyze(alert: dict, model: str, mode: str, threshold: float) -> dict:
    a = unwrap(alert)
    rule = a.get("rule") if isinstance(a.get("rule"), dict) else {}
    rid, level = str(rule.get("id", "")), rule.get("level")
    rmap, default = _rule_map()
    sop = rmap.get(rid, default)
    fallback = rid not in rmap
    action = ACTION_BY_SOP.get(sop, "REVIEW_LOG")
    sev = "Low" if sop == "sop_benign_activity" else level_bucket(level)
    rule_sev = level_bucket(level)
    ip = valid_ip((a.get("data") or {}).get("srcip")) if isinstance(a.get("data"), dict) else None
    notes: list[str] = []
    blob = json.dumps(a, ensure_ascii=False)
    injected = bool(_INJECTION.search(blob))
    if action == "BLOCK_IP" and not ip:
        action = "REVIEW_LOG"; notes.append("BLOCK_IP hạ về REVIEW_LOG vì alert không có IP nguồn hợp lệ.")
    try:
        if action == "NO_ACTION" and int(level) >= 12:
            action = "REVIEW_LOG"; notes.append("NO_ACTION nâng về REVIEW_LOG vì rule.level ≥ 12.")
    except (TypeError, ValueError):
        pass
    report = (
        "**(Báo cáo MÔ PHỎNG, chưa phải kết quả của LLM)**\n\n"
        f"## Tóm tắt\nCảnh báo rule {rid} (level {level}) được gán SOP `{sop}`.\n\n"
        f"## Cách xác minh (trích SOP)\n{_sop_section(sop, 'Cách xác minh') or '(không đọc được SOP)'}\n\n"
        f"## Ngăn chặn (trích SOP)\n{_sop_section(sop, 'Ngăn chặn') or '(không đọc được SOP)'}\n"
    )
    return {
        "ok": True, "error": None,
        "alert_summary": {"rule_id": rid, "level": level, "srcip": ip},
        "attack_type": ATTACK_BY_SOP.get(sop, "Chưa phân loại") + " (mock)",
        "summary": f"[MOCK] Cảnh báo rule {rid} thuộc nhóm {ATTACK_BY_SOP.get(sop, 'chưa phân loại')}.",
        "severity": sev, "rule_severity": rule_sev, "severity_mismatch": sev != rule_sev,
        "recommended_action": action, "action_target_ip": ip if action == "BLOCK_IP" else None,
        "needs_human_confirm": action in ("ISOLATE_HOST",),
        "sop_id": sop, "sop_distance": 0.62 if fallback else 0.22, "sop_is_fallback": fallback,
        "sop_alternatives": [{"sop_id": "sop_general", "distance": 0.66}] if not fallback else [],
        "margin": None, "report_md": report, "guard_notes": notes,
        "suspected_injection": injected, "truncated": False,
        "timings": {"t_retrieve": 0.01, "t_llm": 0.0, "t_total": 0.01},
        "meta": {"model": "MOCK", "prompt_version": "mock", "threshold": threshold, "retrieval_mode": mode},
    }
