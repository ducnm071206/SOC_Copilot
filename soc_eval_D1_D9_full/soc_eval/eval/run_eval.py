#!/usr/bin/env python3
"""
D4 [P0] Bo thuc nghiem - eval/run_eval.py

Chay tung alert (theo split dev/test trong data/labels.csv) qua analyze_alert
(eval/analyzer.py) voi 1 to hop (model, mode retrieval) cu the, ghi KET QUA
TUNG DONG vao file JSONL: dau vao (alert goc), dau ra (raw + parsed), thoi
gian, model, mode, digest model, prompt_version, git commit, phien ban Ollama.

RESUMABLE: neu chay lai voi cung --out, script se doc cac dong da co, BO QUA
cac (alert_ref, model, mode, split) da chay thanh cong roi, chi chay tiep phan
con thieu. An toan khi bi ngat giua chung (vd sau vai gio chay 7b tren CPU).

Cach danh dau "cold start": moi dong duoc gan `call_index_in_run` (thu tu goi
trong CHINH LAN CHAY NAY cho tung to hop model+mode). eval/metrics.py se loai
`call_index_in_run == 1` (cua tung to hop model+mode, gop ca cac lan chay truoc
neu resume) ra khoi thong ke do tre, dung nhu checklist yeu cau "bo luot goi
dau tien (khoi dong nguoi) khoi thong ke do tre".

QUAN TRONG - MOI TRUONG HIEN TAI KHONG CO OLLAMA THAT:
Script nay da duoc TEST DAY DU voi --backend mock (xem output ben duoi). Voi
--backend ollama, code goi dung Ollama REST API (xem eval/analyzer.py) nhung
CHUA duoc chay that vi khong co Ollama/model trong moi truong nay. Khi chay
tren may that: `pip install requests --break-system-packages`, dam bao
`ollama serve` dang chay va da `ollama pull <model>`.

Usage (test voi mock, chay ngay duoc):
    python3 eval/run_eval.py --model mock-model --mode rule_map --split dev \
        --backend mock --out data/eval_runs/mock_rule_map_dev.jsonl

Usage (chay that, tren may co Ollama):
    python3 eval/run_eval.py --model qwen2.5:3b --mode rag --split test \
        --backend ollama --ollama-host http://localhost:11434 \
        --out data/eval_runs/qwen2.5-3b_rag_test.jsonl
"""
from __future__ import annotations

import argparse
import csv
import json
import subprocess
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from analyzer import get_analyzer  # noqa: E402
from retrieval import get_context  # noqa: E402


def get_git_commit() -> str | None:
    try:
        out = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, timeout=5)
        if out.returncode == 0:
            return out.stdout.strip()
    except Exception:  # noqa: BLE001
        pass
    return None


def get_ollama_version(host: str) -> str | None:
    try:
        import requests
        r = requests.get(f"{host}/api/version", timeout=5)
        if r.ok:
            return r.json().get("version")
    except Exception:  # noqa: BLE001
        pass
    return None


def get_model_digest(host: str, model: str) -> str | None:
    try:
        import requests
        r = requests.post(f"{host}/api/show", json={"name": model}, timeout=10)
        if r.ok:
            return r.json().get("digest")
    except Exception:  # noqa: BLE001
        pass
    return None


def load_labels(path: Path, split: str) -> list[dict]:
    rows = []
    with path.open(encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if split != "all" and row.get("split") != split:
                continue
            rows.append(row)
    return rows


def load_adversarial_as_rows(adv_dir: Path) -> list[dict]:
    """Bien moi file .json trong data/adversarial/ thanh 1 'row' cung dinh dang voi
    labels.csv (chi can alert_ref + rule_id) de tai su dung chung pipeline chay eval."""
    rows = []
    for fp in sorted(adv_dir.glob("*.json")):
        try:
            alert = json.loads(fp.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        # alert co the bi boc (_source / hits.hits[]._source) hoac khong phai Wazuh -
        # co gang lay rule.id neu co, khong bat buoc.
        rule_id = ""
        if isinstance(alert, dict):
            rule_id = ((alert.get("rule") or {}).get("id")
                       or (alert.get("_source", {}) or {}).get("rule", {}).get("id", "")
                       or "")
        rows.append({"alert_ref": str(fp), "rule_id": rule_id, "split": "adversarial"})
    return rows


def load_done_keys(out_path: Path) -> set[tuple]:
    """Doc file ket qua da co (neu ton tai) de biet nhung gi da chay THANH CONG roi."""
    done = set()
    if not out_path.exists():
        return done
    with out_path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get("error") is None:  # chi coi la "da xong" neu KHONG loi; loi thi chay lai
                key = (rec.get("alert_ref"), rec.get("model"), rec.get("mode"), rec.get("split"), rec.get("threshold"))
                done.add(key)
    return done


def load_call_index_state(out_path: Path) -> dict:
    """Dem so lan da goi THANH CONG cho tung (model, mode) tu cac lan chay TRUOC, de
    lan chay nay tiep tuc danh so call_index_in_run dung, khong bi tinh nham 'cold start'
    lan thu 2 la lan dau tien cua lan resume."""
    counts = defaultdict(int)
    if not out_path.exists():
        return counts
    with out_path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get("error") is None:
                counts[(rec.get("model"), rec.get("mode"))] += 1
    return counts


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--model", required=True, help="Ten model (vd 'qwen2.5:3b', hoac ten bat ky khi dung mock)")
    ap.add_argument("--mode", required=True, choices=["none", "rule_map", "full_context", "rag"])
    ap.add_argument("--split", required=True, choices=["dev", "test", "all", "adversarial"])
    ap.add_argument("--backend", default="mock", choices=["mock", "ollama"])
    ap.add_argument("--out", type=Path, required=True, help="File JSONL ket qua (se APPEND neu da ton tai)")
    ap.add_argument("--labels", type=Path, default=Path("data/labels.csv"))
    ap.add_argument("--adversarial-dir", type=Path, default=Path("data/adversarial"))
    ap.add_argument("--sop-dir", type=Path, default=Path("data/sop"))
    ap.add_argument("--rag-k", type=int, default=3)
    ap.add_argument("--ollama-host", default="http://localhost:11434")
    ap.add_argument("--mock-seed", type=int, default=42)
    ap.add_argument("--threshold", type=float, default=None,
                     help="Nguong quyet dinh cho E5 (0.2-0.7). None = khong dung threshold "
                          "(hanh vi cu, tuong thich nguoc).")
    ap.add_argument("--limit", type=int, default=None, help="Chi chay N alert dau tien (de test nhanh)")
    args = ap.parse_args()

    if args.split == "adversarial":
        if not args.adversarial_dir.exists():
            print(f"[LOI] Khong thay thu muc adversarial: {args.adversarial_dir}", file=sys.stderr)
            sys.exit(1)
        rows = load_adversarial_as_rows(args.adversarial_dir)
    else:
        if not args.labels.exists():
            print(f"[LOI] Khong thay {args.labels}", file=sys.stderr)
            sys.exit(1)
        rows = load_labels(args.labels, args.split)
    if args.limit:
        rows = rows[: args.limit]
    print(f"Se xu ly {len(rows)} alert (split={args.split}, model={args.model}, mode={args.mode}, backend={args.backend}).")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    done_keys = load_done_keys(args.out)
    call_index_counts = load_call_index_state(args.out)
    if done_keys:
        print(f"Phat hien {len(done_keys)} ket qua da co san trong {args.out} (tu lan chay truoc) - se bo qua.")

    analyzer = get_analyzer(args.backend, host=args.ollama_host) if args.backend == "ollama" \
        else get_analyzer(args.backend, seed=args.mock_seed)

    git_commit = get_git_commit()
    ollama_version = get_ollama_version(args.ollama_host) if args.backend == "ollama" else None
    model_digest = get_model_digest(args.ollama_host, args.model) if args.backend == "ollama" else "mock-no-digest"
    run_started_at = datetime.now(timezone.utc).isoformat()

    if git_commit is None:
        print("[CANH BAO] Khong xac dinh duoc git commit (co the chua init git repo). "
              "Nen `git init && git add -A && git commit` truoc khi chay eval that de tai lap duoc (D7).")
    if args.backend == "ollama" and ollama_version is None:
        print("[CANH BAO] Khong lay duoc phien ban Ollama (co dang chay 'ollama serve' khong?).")

    n_processed = 0
    n_skipped = 0
    n_error = 0
    t_run_start = time.monotonic()

    with args.out.open("a", encoding="utf-8") as fout:
        for i, row in enumerate(rows, start=1):
            alert_ref = row["alert_ref"]
            key = (alert_ref, args.model, args.mode, args.split, args.threshold)
            if key in done_keys:
                n_skipped += 1
                continue

            alert_path = Path(alert_ref)
            if not alert_path.exists():
                print(f"[CANH BAO] Khong tim thay file alert: {alert_path} - bo qua dong nay.", file=sys.stderr)
                continue
            alert = json.loads(alert_path.read_text(encoding="utf-8"))

            context_block = get_context(alert, args.mode, args.sop_dir, rag_k=args.rag_k)

            call_index_counts[(args.model, args.mode)] += 1
            call_index_in_run = call_index_counts[(args.model, args.mode)]

            t0 = time.monotonic()
            result = analyzer.analyze(alert, model=args.model, context_block=context_block, mode=args.mode,
                                       threshold=args.threshold)
            wall_elapsed = time.monotonic() - t0

            record = {
                "alert_ref": alert_ref,
                "rule_id": row.get("rule_id"),
                "split": args.split,
                "model": args.model,
                "mode": args.mode,
                "threshold": args.threshold,
                "backend": args.backend,
                "call_index_in_run": call_index_in_run,  # ==1 -> cold start, metrics.py se loai khoi latency stats
                "run_started_at": run_started_at,
                "record_timestamp": datetime.now(timezone.utc).isoformat(),
                "latency_seconds": result.latency_seconds,
                "wall_elapsed_seconds": wall_elapsed,
                "model_digest": model_digest,
                "ollama_version": ollama_version,
                "git_commit": git_commit,
                "prompt_version": result.prompt_version,
                "input_alert": alert,
                "context_block_preview": (context_block[:300] + "...") if len(context_block) > 300 else context_block,
                "raw_output": result.raw_output,
                "parsed_output": result.parsed,
                "error": result.error,
            }
            fout.write(json.dumps(record, ensure_ascii=False) + "\n")
            fout.flush()  # ghi ngay, khong mat neu bi ngat giua chung

            n_processed += 1
            if result.error:
                n_error += 1
                # loi thi KHONG tinh vao call_index thanh cong, de lan sau resume dung lai dung so
                call_index_counts[(args.model, args.mode)] -= 1

            if i % 10 == 0 or i == len(rows):
                elapsed = time.monotonic() - t_run_start
                print(f"  [{i}/{len(rows)}] da xu ly {n_processed}, bo qua {n_skipped}, "
                      f"loi {n_error} (thoi gian chay: {elapsed:.1f}s)")

    print(f"\nHoan tat. Xu ly moi: {n_processed}, bo qua (da co): {n_skipped}, loi: {n_error}.")
    print(f"Ket qua: {args.out}")
    if n_error:
        print(f"[CANH BAO] {n_error} dong bi loi (xem truong 'error' trong file JSONL) - "
              "chay lai CUNG LENH nay se TU DONG thu lai cac dong loi (khong bi coi la 'da xong').")


if __name__ == "__main__":
    main()
