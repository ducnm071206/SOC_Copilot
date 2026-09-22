"""ui/backend.py: lớp nối giữa giao diện và lõi pipeline của Bình.

Giao diện chỉ gọi các hàm ở đây, không import trực tiếp soc_copilot ở nơi khác. Nếu chưa có `soc_copilot.core`
thì tự dùng backend GIẢ (ui/mock_backend.py) và giao diện hiện cảnh báo rõ ràng.

HỢP ĐỒNG với Bình (xem docs/GIAO_DIEN_VOI_BINH.md):
  soc_copilot.core.analyze_alert(alert, model=..., threshold=..., retrieval=...) -> AnalysisResult (pydantic) hoặc dict
  soc_copilot.llm.health() -> dict {ok: bool, version: str|None, models: list[str], error: str|None}
  soc_copilot.config: THRESHOLD, DEFAULT_MODEL, PROTECTED_IPS (đều tuỳ chọn ở phía giao diện)
"""
from __future__ import annotations

from typing import Any, Optional

from . import mock_backend

MODES = {
    "rag": "RAG (truy xuất ngữ nghĩa)",
    "rule_map": "Baseline: tra theo rule.id",
    "full_context": "Baseline: đưa toàn bộ SOP vào prompt",
}

_IMPORT_ERROR: Optional[str] = None
try:  # pragma: no cover - phụ thuộc repo của Bình
    from soc_copilot.core import analyze_alert as _analyze_alert  # type: ignore
    from soc_copilot import llm as _llm  # type: ignore
    _REAL = True
except Exception as _e:  # ImportError hoặc lỗi khác khi import
    _analyze_alert = None
    _llm = None
    _REAL = False
    _IMPORT_ERROR = f"{type(_e).__name__}: {_e}"

try:  # pragma: no cover
    from soc_copilot import config as _config  # type: ignore
except Exception:
    _config = None


def is_real() -> bool:
    return _REAL


def import_error() -> Optional[str]:
    return _IMPORT_ERROR


def cfg(name: str, default: Any = None) -> Any:
    return getattr(_config, name, default) if _config is not None else default


def to_dict(result: Any) -> dict:
    """AnalysisResult (pydantic v2/v1) hoặc dict -> dict thuần."""
    if isinstance(result, dict):
        return result
    for attr in ("model_dump", "dict"):
        fn = getattr(result, attr, None)
        if callable(fn):
            try:
                return fn()
            except Exception:
                continue
    return dict(getattr(result, "__dict__", {}))


def health() -> dict:
    """Trạng thái Ollama, luôn trả về dict đủ khoá."""
    out = {"ok": False, "version": None, "models": [], "error": None}
    try:
        h = _llm.health() if _REAL else mock_backend.health()
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {e}"
        return out
    if isinstance(h, bool):
        out["ok"] = h
    elif isinstance(h, dict):
        out["ok"] = bool(h.get("ok", h.get("online", False)))
        out["version"] = h.get("version")
        models = h.get("models") or []
        out["models"] = [m if isinstance(m, str) else str(m.get("name", m)) if isinstance(m, dict) else str(m) for m in models]
        out["error"] = h.get("error")
    return out


def analyze(alert: dict, model: Optional[str], mode: str, threshold: float) -> dict:
    """Luôn trả về dict; không ném exception (lỗi nằm trong result['error'])."""
    try:
        if _REAL:
            res = _analyze_alert(alert, model=model, threshold=threshold, retrieval=mode)
            return to_dict(res)
        return mock_backend.analyze(alert, model or "mock-model", mode, threshold)
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}", "attack_type": "", "guard_notes": [],
                "meta": {"model": model, "retrieval_mode": mode}}
