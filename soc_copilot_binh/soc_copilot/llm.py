"""B5: gọi Ollama /api/chat bằng requests, ép JSON theo schema pydantic."""
import json
import re
import time
from dataclasses import dataclass
from typing import List, Optional

import requests

from . import config
from .models import LLMOutput


@dataclass
class LLMResult:
    output: Optional[LLMOutput] = None
    prompt_eval_count: Optional[int] = None
    eval_count: Optional[int] = None
    total_duration: Optional[int] = None     # ns, theo Ollama
    truncated: bool = False
    t_llm: float = 0.0
    error: Optional[str] = None


def build_schema(sop_ids: Optional[List[str]] = None) -> dict:
    schema = LLMOutput.model_json_schema()
    props = schema.setdefault("properties", {})
    if sop_ids:
        props["chosen_sop_id"] = {"type": "string", "enum": list(sop_ids)}
        req = schema.setdefault("required", [])
        if "chosen_sop_id" not in req:
            req.append("chosen_sop_id")
    else:
        props.pop("chosen_sop_id", None)
    return schema


def _payload(messages, model, schema) -> dict:
    return {"model": model, "messages": messages, "stream": False,
            "format": schema, "keep_alive": config.KEEP_ALIVE,
            "options": {"temperature": 0, "seed": config.SEED, "num_ctx": config.NUM_CTX}}


def call_llm(messages: List[dict], model: str = config.DEFAULT_MODEL,
             sop_ids: Optional[List[str]] = None) -> LLMResult:
    """Không ném exception. JSON hỏng thì thử lại 1 lần rồi trả error."""
    schema = build_schema(sop_ids)
    url = f"{config.OLLAMA_URL}/api/chat"
    res = LLMResult()
    t0 = time.perf_counter()
    last_err = None
    for attempt in range(2):
        try:
            r = requests.post(url, json=_payload(messages, model, schema),
                              timeout=config.LLM_TIMEOUT)
        except requests.exceptions.ConnectionError:
            res.error = f"Không kết nối được Ollama tại {config.OLLAMA_URL}. Ollama đã chạy chưa?"
            break
        except requests.exceptions.Timeout:
            res.error = f"Ollama không phản hồi sau {config.LLM_TIMEOUT}s (timeout)"
            break
        except requests.exceptions.RequestException as e:
            res.error = f"Lỗi gọi Ollama: {e}"
            break

        if r.status_code == 404:
            res.error = f"Model '{model}' chưa có trên Ollama. Chạy: ollama pull {model}"
            break
        if r.status_code >= 400:
            res.error = f"Ollama trả HTTP {r.status_code}: {r.text[:200]}"
            break

        try:
            data = r.json()
            res.prompt_eval_count = data.get("prompt_eval_count")
            res.eval_count = data.get("eval_count")
            res.total_duration = data.get("total_duration")
            if res.prompt_eval_count is not None and \
                    res.prompt_eval_count >= config.NUM_CTX * config.TRUNCATION_RATIO:
                res.truncated = True
            out = LLMOutput.model_validate(json.loads(data["message"]["content"]))
            if sop_ids and out.chosen_sop_id not in sop_ids:
                raise ValueError(f"chosen_sop_id không hợp lệ: {out.chosen_sop_id!r}")
            res.output, res.error = out, None
            break
        except (ValueError, KeyError, TypeError) as e:
            last_err = f"LLM trả JSON không hợp lệ: {e}"
            res.error = last_err            # vòng sau thử lại 1 lần
    res.t_llm = time.perf_counter() - t0
    return res


def _version_tuple(v: str):
    m = re.match(r"(\d+)\.(\d+)\.(\d+)", v or "")
    return tuple(int(x) for x in m.groups()) if m else None


def health() -> dict:
    out = {"ok": False, "version": None, "schema_ok": False, "models": [], "error": None}
    try:
        v = requests.get(f"{config.OLLAMA_URL}/api/version", timeout=5).json().get("version")
        out["version"] = v
        vt = _version_tuple(v)
        out["schema_ok"] = bool(vt and vt >= config.MIN_OLLAMA_VERSION)
        out["models"] = list_models()
        out["ok"] = True
        if not out["schema_ok"]:
            out["error"] = f"Ollama {v} quá cũ, cần >= {'.'.join(map(str, config.MIN_OLLAMA_VERSION))} để dùng JSON schema"
    except requests.exceptions.RequestException as e:
        out["error"] = f"Không kết nối được Ollama: {e}"
    except ValueError as e:
        out["error"] = f"Phản hồi Ollama không hợp lệ: {e}"
    return out


def list_models() -> List[str]:
    try:
        r = requests.get(f"{config.OLLAMA_URL}/api/tags", timeout=5)
        return sorted(m["name"] for m in r.json().get("models", []))
    except (requests.exceptions.RequestException, ValueError, KeyError):
        return []
