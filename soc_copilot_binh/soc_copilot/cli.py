import argparse
import json
import sys

from . import config


def main(argv=None):
    p = argparse.ArgumentParser(prog="soc_copilot.cli")
    sub = p.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("analyze", help="phân tích một file alert JSON")
    a.add_argument("file")
    a.add_argument("--model", default=config.DEFAULT_MODEL)
    a.add_argument("--mode", default="rag", choices=["rag", "rule_map", "full_context"])
    a.add_argument("--threshold", type=float, default=config.THRESHOLD)
    sub.add_parser("sync", help="đồng bộ data/sops/*.md vào Chroma")
    sub.add_parser("health", help="kiểm tra Ollama")
    args = p.parse_args(argv)

    if args.cmd == "analyze":
        from .core import analyze_alert
        with open(args.file, encoding="utf-8-sig") as f:
            alert = json.load(f)
        res = analyze_alert(alert, args.model, args.threshold, args.mode)
        print(res.model_dump_json(indent=2))
        return 1 if res.error else 0
    if args.cmd == "sync":
        from .sop_store import SopStore
        print(json.dumps(SopStore().sync(), ensure_ascii=False, indent=2))
        return 0
    if args.cmd == "health":
        from .llm import health
        h = health()
        print(json.dumps(h, ensure_ascii=False, indent=2))
        return 0 if h["ok"] and h["schema_ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
