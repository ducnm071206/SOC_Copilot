"""B7: pipeline hoàn chỉnh B3 -> B4 -> B5 -> B6. Không bao giờ ném exception ra ngoài."""
import threading
import time
from typing import Callable, List, Optional

from . import config
from .features import normalize_alert, compact_alert
from .guard import apply_guard
from .llm import call_llm
from .models import AnalysisResult
from .prompts import build_messages
from .retrieval import retrieve

_store = None
_store_lock = threading.Lock()


def get_store():
    """Khởi tạo kho SOP một lần (sync khi khởi động)."""
    global _store
    with _store_lock:
        if _store is None:
            from .sop_store import SopStore
            s = SopStore()
            s.sync()
            _store = s
        return _store


def analyze_alert(alert: dict, model: str = config.DEFAULT_MODEL,
                  threshold: float = config.THRESHOLD, retrieval: str = "rag",
                  *, store=None, llm_fn: Optional[Callable] = None,
                  rule_map: Optional[dict] = None) -> AnalysisResult:
    t0 = time.perf_counter()
    res = AnalysisResult(model=model, prompt_version=config.PROMPT_VERSION,
                         threshold=threshold, retrieval_mode=retrieval)
    try:
        a = normalize_alert(alert)
        compact = compact_alert(a)
        store = store or get_store()

        t1 = time.perf_counter()
        r = retrieve(a, store, retrieval, threshold, rule_map)
        res.t_retrieve = time.perf_counter() - t1
        res.sop_id, res.sop_distance = r.sop_id, r.distance
        res.margin, res.alternatives = r.margin, r.alternatives
        if r.used_fallback:
            res.guard_notes.append(f"Dùng SOP dự phòng {config.FALLBACK_SOP_ID} (không có SOP đủ gần)")

        sop_ids = [d["id"] for d in r.sop_docs] if r.mode == "full_context" else None
        l = (llm_fn or call_llm)(build_messages(compact, r), model, sop_ids)
        res.t_llm = l.t_llm
        res.prompt_eval_count, res.eval_count = l.prompt_eval_count, l.eval_count
        res.truncated = l.truncated
        if l.truncated:
            res.guard_notes.append("Prompt có thể bị cắt (prompt_eval_count gần num_ctx)")
        if l.error or l.output is None:
            res.error = l.error or "LLM không trả kết quả"
            return res

        out = l.output
        if r.mode == "full_context":
            res.sop_id = out.chosen_sop_id
        g = apply_guard(a, out.severity, out.recommended_action)
        res.reasoning = out.reasoning
        res.llm_severity, res.llm_action = out.severity, out.recommended_action
        res.severity, res.recommended_action = g.severity, g.action
        res.block_target, res.ip_source = g.block_target, g.ip_source
        res.needs_human_confirm = g.needs_human_confirm
        res.rule_bucket = g.rule_bucket
        res.severity_mismatch = g.severity_mismatch
        res.suspected_injection = g.suspected_injection
        res.guard_notes.extend(g.notes)
    except Exception as e:
        res.error = f"{type(e).__name__}: {e}"
    finally:
        res.t_total = time.perf_counter() - t0
    return res


def analyze_batch(alerts: List[dict], **kw) -> List[AnalysisResult]:
    return [analyze_alert(a, **kw) for a in alerts]
