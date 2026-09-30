"""B9: chạy toàn bộ luồng và liệt kê mọi kết nối ra ngoài localhost.
Chạy:  python scripts/egress_check.py [--offline] [--modes rag,rule_map,full_context]
Kỳ vọng: 0 kết nối ngoài. Cần Ollama đang chạy trên localhost để luồng chạy đủ."""
import argparse
import glob
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

p = argparse.ArgumentParser()
p.add_argument("--offline", action="store_true", help="đặt HF_HUB_OFFLINE=1 (chạy lần 2)")
p.add_argument("--modes", default="rag")
p.add_argument("--samples", default="data/samples/*.json")
p.add_argument("--model", default=None)
args = p.parse_args()
if args.offline:
    os.environ["HF_HUB_OFFLINE"] = "1"
    os.environ["TRANSFORMERS_OFFLINE"] = "1"

from soc_copilot import config                       # noqa: E402
from soc_copilot.netguard import EgressGuard         # noqa: E402

FALLBACK = {"rule": {"id": "5710", "level": 5, "description": "sshd: non-existent user"},
            "data": {"srcip": "203.0.113.5"}, "full_log": "sshd: Failed password from 203.0.113.5"}
alerts = []
for f in sorted(glob.glob(args.samples)):
    with open(f, encoding="utf-8-sig") as fh:
        alerts.append(json.load(fh))
alerts = alerts or [FALLBACK]

ran, errors = 0, []
with EgressGuard(block=True) as g:
    from soc_copilot.core import analyze_alert, get_store
    from soc_copilot.llm import health
    try:
        get_store()
    except Exception as e:
        errors.append(f"get_store: {type(e).__name__}: {e}")
    health()
    for mode in args.modes.split(","):
        for a in alerts:
            r = analyze_alert(a, args.model or config.DEFAULT_MODEL, retrieval=mode.strip())
            ran += 1
            if r.error:
                errors.append(f"[{mode}] {r.error}")

print(f"Đã chạy {ran} lần phân tích, {len(errors)} lỗi.")
for e in sorted(set(errors)):
    print("  lỗi:", e)
if g.attempts:
    print("KẾT NỐI RA NGOÀI (đã bị chặn):")
    for kind, host in sorted(set(g.attempts)):
        print(f"  {kind:8} {host}")
    sys.exit(1)
print("Không có kết nối ra ngoài localhost.")
if errors:
    print("Lưu ý: luồng chưa chạy đủ (có lỗi ở trên), kết luận chưa đáng tin.")
    sys.exit(2)
