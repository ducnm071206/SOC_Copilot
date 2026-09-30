"""B6: kiểm tra sau khi LLM trả lời. LLM không tự đưa IP; IP lấy từ alert."""
import json
import re
from dataclasses import dataclass, field
from typing import List, Optional

from . import config
from .features import extract_src_ip, _level

SEV_ORDER = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}
_INJECTION = re.compile(
    r"ignore (?:all |the )?(?:previous|prior|above)|disregard (?:the )?(?:previous|above)|"
    r"\bsystem\s*:|recommended_action|you are now|new instructions?|"
    r"\bno_action\b|do not (?:block|report)", re.I)


@dataclass
class GuardResult:
    severity: str
    action: str
    block_target: Optional[str] = None
    ip_source: str = "none"
    needs_human_confirm: bool = False
    rule_bucket: str = "Low"
    severity_mismatch: bool = False
    suspected_injection: bool = False
    notes: List[str] = field(default_factory=list)


def level_bucket(level: int) -> str:
    for mx, name in config.LEVEL_BUCKETS:
        if level <= mx:
            return name
    return config.LEVEL_BUCKETS[-1][1]


def detect_injection(a: dict) -> bool:
    return bool(_INJECTION.search(json.dumps(a, ensure_ascii=False, default=str)))


def apply_guard(alert: dict, severity: str, action: str) -> GuardResult:
    level = _level(alert)
    ip, ip_src = extract_src_ip(alert)
    g = GuardResult(severity=severity, action=action, ip_source=ip_src,
                    rule_bucket=level_bucket(level))

    if action == "BLOCK_IP":
        if ip is None:
            g.action = "REVIEW_LOG"
            g.notes.append("BLOCK_IP hạ về REVIEW_LOG: không có IP nguồn hợp lệ")
        elif ip in config.PROTECTED_IPS:
            g.action = "REVIEW_LOG"
            g.notes.append(f"BLOCK_IP hạ về REVIEW_LOG: {ip} thuộc PROTECTED_IPS")
        else:
            g.block_target = ip
    elif action == "NO_ACTION" and level > config.NO_ACTION_MAX_LEVEL:
        g.action = "REVIEW_LOG"
        g.notes.append(f"NO_ACTION nâng lên REVIEW_LOG: rule.level={level} >= 12")
    elif action == "ISOLATE_HOST":
        if SEV_ORDER[severity] >= SEV_ORDER["High"]:
            g.needs_human_confirm = True
            g.notes.append("ISOLATE_HOST: cần người xác nhận")
        else:
            g.action = "REVIEW_LOG"
            g.notes.append(f"ISOLATE_HOST hạ về REVIEW_LOG: severity={severity} < High")

    if severity != g.rule_bucket:
        g.severity_mismatch = True
        g.notes.append(f"Severity lệch: LLM={severity}, rule.level={level} -> {g.rule_bucket}")

    if detect_injection(alert):
        g.suspected_injection = True
        g.notes.append("Nghi ngờ prompt injection trong dữ liệu alert (heuristic, chỉ là tín hiệu)")
    return g
