"""B4: 3 chế độ truy xuất SOP (rag / rule_map / full_context), cùng một cấu trúc trả về."""
from dataclasses import dataclass, field
from typing import List, Optional

import yaml

from . import config
from .features import build_query


class RetrievalError(Exception):
    pass


@dataclass
class Retrieval:
    mode: str
    sop_id: Optional[str]                 # None ở full_context cho tới khi LLM chọn
    distance: Optional[float] = None
    margin: Optional[float] = None        # d2 - d1
    alternatives: List[dict] = field(default_factory=list)
    sop_docs: List[dict] = field(default_factory=list)   # [{id, document}] đưa vào prompt
    used_fallback: bool = False


def _fallback(store) -> dict:
    doc = store.get_sop(config.FALLBACK_SOP_ID)
    if not doc:
        raise RetrievalError(f"Thiếu SOP dự phòng '{config.FALLBACK_SOP_ID}' trong kho")
    return doc


def retrieve_rag(alert: dict, store, threshold: float) -> Retrieval:
    hits = store.query(build_query(alert), n_results=config.RETRIEVAL_TOP_K)
    if not hits:
        doc = _fallback(store)
        return Retrieval("rag", doc["id"], sop_docs=[doc], used_fallback=True)
    d1 = hits[0]["distance"]
    margin = hits[1]["distance"] - d1 if len(hits) > 1 else None
    alts = [{"sop_id": h["id"], "distance": h["distance"]} for h in hits[1:]]
    if d1 <= threshold:
        doc = store.get_sop(hits[0]["id"])
        return Retrieval("rag", hits[0]["id"], d1, margin, alts, [doc])
    doc = _fallback(store)   # collection.get theo id, không query lại bằng chuỗi
    return Retrieval("rag", doc["id"], d1, margin, alts, [doc], used_fallback=True)


def load_rule_map(path=config.RULE_MAP_PATH) -> dict:
    """Chấp nhận {"rules": {id: sop}} hoặc {id: sop}."""
    try:
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except FileNotFoundError:
        raise RetrievalError(f"Không thấy rule_map: {path}")
    if isinstance(data.get("rules"), dict):
        data = data["rules"]
    return {str(k): str(v) for k, v in data.items()}


def retrieve_rule_map(alert: dict, store, rule_map: Optional[dict] = None) -> Retrieval:
    rule_map = load_rule_map() if rule_map is None else rule_map
    rid = str(alert["rule"]["id"])
    sop_id = rule_map.get(rid)
    doc = store.get_sop(sop_id) if sop_id else None
    if doc:
        return Retrieval("rule_map", sop_id, sop_docs=[doc])
    doc = _fallback(store)
    return Retrieval("rule_map", doc["id"], sop_docs=[doc], used_fallback=True)


def retrieve_full_context(store) -> Retrieval:
    docs = store.all_sops()
    if not docs:
        raise RetrievalError("Kho SOP rỗng")
    return Retrieval("full_context", None, sop_docs=docs)


def retrieve(alert: dict, store, mode: str = "rag",
             threshold: float = config.THRESHOLD,
             rule_map: Optional[dict] = None) -> Retrieval:
    if mode == "rag":
        return retrieve_rag(alert, store, threshold)
    if mode == "rule_map":
        return retrieve_rule_map(alert, store, rule_map)
    if mode == "full_context":
        return retrieve_full_context(store)
    raise RetrievalError(f"retrieval_mode không hợp lệ: {mode}")
