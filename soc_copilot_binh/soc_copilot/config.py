"""Cấu hình tập trung. Các giá trị có ghi chú TODO cần nhóm thống nhất."""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

EMBED_MODEL = "sentence-transformers/all-MiniLM-L6-v2"   # TODO: chốt model embedding
OLLAMA_URL = "http://localhost:11434"
DEFAULT_MODEL = "qwen2.5:7b"                              # TODO: chốt model mặc định
NUM_CTX = 4096
THRESHOLD = 0.45            # TODO: cosine distance; chỉnh theo kết quả eval
PROMPT_VERSION = "v1"
DB_PATH = str(ROOT / "soc_copilot.db")
CHROMA_PATH = str(ROOT / "chroma_data")
SOP_DIR = ROOT / "data" / "sops"
RULE_MAP_PATH = ROOT / "data" / "rule_map.yaml"

# IP không bao giờ được chặn (gateway, DNS, máy quản trị...). TODO: điền thật.
PROTECTED_IPS = {"127.0.0.1", "::1", "10.0.0.1", "192.168.1.1"}

# Chính sách của nhóm (không phải chuẩn Wazuh): (level tối đa, nhãn)
LEVEL_BUCKETS = [(4, "Low"), (7, "Medium"), (11, "High"), (10**6, "Critical")]
NO_ACTION_MAX_LEVEL = 11    # NO_ACTION với level >= 12 bị nâng lên REVIEW_LOG

FALLBACK_SOP_ID = "sop_general"
RETRIEVAL_TOP_K = 3
LLM_TIMEOUT = 120
KEEP_ALIVE = "30m"
SEED = 42
TRUNCATION_RATIO = 0.95     # prompt_eval_count >= NUM_CTX * ratio => nghi prompt bị cắt
MIN_OLLAMA_VERSION = (0, 5, 0)   # cần cho JSON schema trong format
