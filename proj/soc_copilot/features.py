"""B3: chuẩn hoá và rút gọn alert Wazuh."""
import ipaddress
import re
from typing import Any, Optional, Tuple

LOG_MAX = 800
URL_MAX = 200
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_IP_CTX = re.compile(
    r"(?:\bsrc(?:ip)?\b|\bfrom\b|\bsource\b|\bclient\b|\brhost\b|\bremote\b)"
    r"\s*[=:]?\s*(\d{1,3}(?:\.\d{1,3}){3})", re.I)


def _get(d: Any, path: str, default=None):
    for k in path.split("."):
        if not isinstance(d, dict) or k not in d:
            return default
        d = d[k]
    return d


def _clean(s: Any, limit: int) -> str:
    s = _CTRL.sub("", str(s if s is not None else ""))
    return s[:limit]


def normalize_alert(raw: Any) -> dict:
    if not isinstance(raw, dict):
        raise ValueError("Alert phải là JSON object (dict)")
    a = raw
    # copy từ Discover: {"_index":..., "_id":..., "_source": {...}}
    if isinstance(a.get("_source"), dict):
        a = a["_source"]
    if _get(a, "rule.id") in (None, ""):
        raise ValueError("Alert thiếu rule.id")
    return a


def _mitre_ids(a: dict) -> list:
    m = _get(a, "rule.mitre.id", [])
    if isinstance(m, str):
        m = [m]
    return [str(x) for x in m] if isinstance(m, list) else []


def _level(a: dict) -> int:
    try:
        return int(_get(a, "rule.level", 0))
    except (TypeError, ValueError):
        return 0


def compact_alert(a: dict) -> dict:
    groups = _get(a, "rule.groups", [])
    out = {
        "rule_id": str(_get(a, "rule.id")),
        "level": _level(a),
        "description": _clean(_get(a, "rule.description", ""), 300),
        "groups": [str(g) for g in groups] if isinstance(groups, list) else [],
        "mitre": _mitre_ids(a),
        "agent": _clean(_get(a, "agent.name", ""), 100),
        "srcip": _clean(_get(a, "data.srcip", ""), 64),
        "url": _clean(_get(a, "data.url", ""), URL_MAX),
        "syscheck_path": _clean(_get(a, "syscheck.path", ""), 300),
        "log": _clean(a.get("full_log", ""), LOG_MAX),
    }
    return {k: v for k, v in out.items() if v not in ("", [], None)}


def build_query(a: dict) -> str:
    c = compact_alert(a)
    parts = [c.get("description", ""), " ".join(c.get("groups", [])),
             " ".join(c.get("mitre", [])), c.get("url", ""),
             c.get("syscheck_path", "")]
    return " | ".join(p for p in parts if p)


def _valid_ip(s: str) -> Optional[str]:
    try:
        return str(ipaddress.ip_address(str(s).strip()))
    except ValueError:
        return None


def extract_src_ip(a: dict) -> Tuple[Optional[str], str]:
    ip = _valid_ip(_get(a, "data.srcip", ""))
    if ip:
        return ip, "data.srcip"
    for field in ("full_log", "previous_output"):
        text = a.get(field) or ""
        for m in _IP_CTX.finditer(str(text)):
            ip = _valid_ip(m.group(1))
            if ip:
                return ip, f"regex:{field}"
    return None, "none"
