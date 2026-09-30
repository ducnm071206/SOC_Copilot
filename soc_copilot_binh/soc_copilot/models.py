from typing import List, Literal, Optional
from pydantic import BaseModel, Field

Severity = Literal["Low", "Medium", "High", "Critical"]
Action = Literal["BLOCK_IP", "ISOLATE_HOST", "REVIEW_LOG", "NO_ACTION"]
RetrievalMode = Literal["rag", "rule_map", "full_context"]


class LLMOutput(BaseModel):
    """Schema đưa cho Ollama (format=). Không có sop_source / IP: hệ thống tự gắn."""
    severity: Severity
    recommended_action: Action
    reasoning: str = ""
    chosen_sop_id: Optional[str] = None   # chỉ dùng ở chế độ full_context


class AnalysisResult(BaseModel):
    # kết quả cuối (sau guard)
    severity: Optional[Severity] = None
    recommended_action: Optional[Action] = None
    reasoning: str = ""
    report_md: Optional[str] = None
    # SOP / retrieval
    sop_id: Optional[str] = None
    sop_distance: Optional[float] = None
    margin: Optional[float] = None
    alternatives: List[dict] = Field(default_factory=list)
    # guard
    block_target: Optional[str] = None
    ip_source: Optional[str] = None
    needs_human_confirm: bool = False
    rule_bucket: Optional[Severity] = None
    llm_severity: Optional[Severity] = None
    llm_action: Optional[Action] = None
    severity_mismatch: bool = False
    suspected_injection: bool = False
    guard_notes: List[str] = Field(default_factory=list)
    # meta
    model: Optional[str] = None
    prompt_version: Optional[str] = None
    threshold: Optional[float] = None
    retrieval_mode: Optional[str] = None
    prompt_eval_count: Optional[int] = None
    eval_count: Optional[int] = None
    truncated: bool = False
    t_retrieve: float = 0.0
    t_llm: float = 0.0
    t_total: float = 0.0
    error: Optional[str] = None
