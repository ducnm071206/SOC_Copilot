#!/usr/bin/env python3
"""
D5 [P0] Ma tran thuc nghiem - eval/run_matrix.py

Dieu phoi cac lenh goi `eval/run_eval.py` (chay tung to hop) va `eval/metrics.py`
(tong hop) de thuc hien 2 thi nghiem P0 trong checklist D5:

  E1: 3 che do truy xuat (rule_map, full_context, rag) x 1 model (mac dinh model
      "3b" - ten model that do ban truyen vao qua --model), tren CA dev va test.
      Cau hoi: RAG co hon rule_map/full_context khong?

  E5: Quet nguong (threshold) 0.2 -> 0.7 (buoc 0.1) CHI TREN split dev, cho 1 to
      hop (model, mode) co dinh (mac dinh la mode tot nhat theo E1 - ban tu chon
      qua --mode sau khi xem ket qua E1). Sau khi CHON duoc nguong tot nhat tren
      dev (dua vao docs/figures/metrics_report.md, TU LAM BANG TAY vi day la
      quyet dinh dua tren so lieu, khong the tu dong hoa mot cach khach quan),
      chay lai 1 LAN DUY NHAT tren split test voi nguong da chon
      (--report-on-test-threshold) de bao cao ket qua cuoi cung.

Script nay CHI GOI LAI eval/run_eval.py nhieu lan (subprocess) - moi loi ich
resumable/checkpoint cua run_eval.py (ghi JSONL tung dong, tiep tuc duoc neu bi
ngat) van giu nguyen cho tung file rieng le trong ma tran.

QUAN TRONG: da tu kiem tra toan bo script nay bang --backend mock (khong can
Ollama). Khi chay that, chi can doi --backend thanh ollama va --model thanh ten
model that (vd qwen2.5:3b) - cau truc lenh khong doi.

Usage - E1 (test voi mock, chay ngay duoc):
    python3 eval/run_matrix.py e1 --model mock-model --backend mock \
        --out-dir data/eval_runs

Usage - E1 that (khi co Ollama):
    python3 eval/run_matrix.py e1 --model qwen2.5:3b --backend ollama \
        --out-dir data/eval_runs

Usage - E5 (quet nguong tren dev, voi mode da chon vd rag):
    python3 eval/run_matrix.py e5 --model qwen2.5:3b --mode rag --backend ollama \
        --out-dir data/eval_runs

Usage - E5 buoc 2, sau khi da xem docs/figures/metrics_report.md va chon nguong
(vi du 0.4 la tot nhat tren dev), chay 1 lan tren test:
    python3 eval/run_matrix.py e5-final --model qwen2.5:3b --mode rag \
        --threshold 0.4 --backend ollama --out-dir data/eval_runs

Sau moi lenh, script TU DONG goi eval/metrics.py de cap nhat
docs/figures/metrics_report.md / .json voi toan bo ket qua da chay.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

E1_MODES = ["rule_map", "full_context", "rag"]
E5_THRESHOLDS = [0.2, 0.3, 0.4, 0.5, 0.6, 0.7]

THIS_DIR = Path(__file__).resolve().parent
RUN_EVAL = THIS_DIR / "run_eval.py"
METRICS = THIS_DIR / "metrics.py"


def run(cmd: list[str]) -> int:
    print(f"\n$ {' '.join(cmd)}")
    t0 = time.monotonic()
    proc = subprocess.run(cmd)
    dt = time.monotonic() - t0
    print(f"  (xong sau {dt:.1f}s, return code {proc.returncode})")
    return proc.returncode


def safe_tag(s: str) -> str:
    return s.replace(":", "-").replace("/", "-")


def cmd_e1(args):
    modes = args.modes or E1_MODES
    splits = args.splits or ["dev", "test"]
    print(f"=== E1: model={args.model} backend={args.backend} modes={modes} splits={splits} ===")
    any_fail = False
    for mode in modes:
        for split in splits:
            out_path = args.out_dir / f"{safe_tag(args.model)}_{mode}_{split}.jsonl"
            cmd = [
                sys.executable, str(RUN_EVAL),
                "--model", args.model, "--mode", mode, "--split", split,
                "--backend", args.backend, "--out", str(out_path),
                "--labels", str(args.labels), "--sop-dir", str(args.sop_dir),
            ]
            if args.ollama_host:
                cmd += ["--ollama-host", args.ollama_host]
            if args.limit:
                cmd += ["--limit", str(args.limit)]
            rc = run(cmd)
            any_fail = any_fail or (rc != 0)
    return not any_fail


def cmd_e5(args):
    thresholds = args.thresholds or E5_THRESHOLDS
    print(f"=== E5 (quet nguong tren DEV): model={args.model} mode={args.mode} "
          f"backend={args.backend} thresholds={thresholds} ===")
    print("LUU Y: E5 CHI chay tren split=dev theo dung checklist ('chon tren dev, bao cao tren test'). "
          "Sau khi xem ket qua, dung 'python3 eval/run_matrix.py e5-final --threshold <gia_tri_da_chon>' "
          "de chay 1 lan tren test.")
    any_fail = False
    for thr in thresholds:
        out_path = args.out_dir / f"{safe_tag(args.model)}_{args.mode}_dev_thr{thr}.jsonl"
        cmd = [
            sys.executable, str(RUN_EVAL),
            "--model", args.model, "--mode", args.mode, "--split", "dev",
            "--backend", args.backend, "--out", str(out_path), "--threshold", str(thr),
            "--labels", str(args.labels), "--sop-dir", str(args.sop_dir),
        ]
        if args.ollama_host:
            cmd += ["--ollama-host", args.ollama_host]
        if args.limit:
            cmd += ["--limit", str(args.limit)]
        rc = run(cmd)
        any_fail = any_fail or (rc != 0)
    return not any_fail


def cmd_e5_final(args):
    if args.threshold is None:
        print("[LOI] e5-final can --threshold <gia tri ban da chon dua tren ket qua tren dev>.",
              file=sys.stderr)
        return False
    print(f"=== E5 buoc cuoi (BAO CAO TREN TEST): model={args.model} mode={args.mode} "
          f"threshold={args.threshold} ===")
    out_path = args.out_dir / f"{safe_tag(args.model)}_{args.mode}_test_thr{args.threshold}.jsonl"
    cmd = [
        sys.executable, str(RUN_EVAL),
        "--model", args.model, "--mode", args.mode, "--split", "test",
        "--backend", args.backend, "--out", str(out_path), "--threshold", str(args.threshold),
        "--labels", str(args.labels), "--sop-dir", str(args.sop_dir),
    ]
    if args.ollama_host:
        cmd += ["--ollama-host", args.ollama_host]
    if args.limit:
        cmd += ["--limit", str(args.limit)]
    rc = run(cmd)
    return rc == 0


def update_metrics(args):
    out_md = args.metrics_out_md if args.metrics_out_md is not None else Path("docs/figures/metrics_report.md")
    out_json = args.metrics_out_json if args.metrics_out_json is not None else Path("docs/figures/metrics_report.json")
    cmd = [
        sys.executable, str(METRICS),
        "--results", str(args.out_dir / "*.jsonl"),
        "--labels", str(args.labels),
        "--out-md", str(out_md), "--out-json", str(out_json),
    ]
    run(cmd)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--model", required=True)
    common.add_argument("--backend", default="mock", choices=["mock", "ollama"])
    common.add_argument("--out-dir", type=Path, default=Path("data/eval_runs"))
    common.add_argument("--labels", type=Path, default=Path("data/labels.csv"))
    common.add_argument("--sop-dir", type=Path, default=Path("data/sop"))
    common.add_argument("--ollama-host", default=None)
    common.add_argument("--limit", type=int, default=None, help="Gioi han so alert/lenh - de test nhanh")
    common.add_argument("--metrics-out-md", type=Path, default=None)
    common.add_argument("--metrics-out-json", type=Path, default=None)

    p_e1 = sub.add_parser("e1", parents=[common], help="3 che do truy xuat x model, tren dev+test")
    p_e1.add_argument("--modes", nargs="+", default=None, help=f"Mac dinh: {E1_MODES}")
    p_e1.add_argument("--splits", nargs="+", default=None, help="Mac dinh: dev test")

    p_e5 = sub.add_parser("e5", parents=[common], help="Quet nguong 0.2-0.7 tren dev cho 1 mode co dinh")
    p_e5.add_argument("--mode", required=True, choices=["none", "rule_map", "full_context", "rag"])
    p_e5.add_argument("--thresholds", nargs="+", type=float, default=None, help=f"Mac dinh: {E5_THRESHOLDS}")

    p_e5f = sub.add_parser("e5-final", parents=[common], help="Chay 1 lan tren test voi nguong da chon")
    p_e5f.add_argument("--mode", required=True, choices=["none", "rule_map", "full_context", "rag"])
    p_e5f.add_argument("--threshold", type=float, default=None, required=True)

    args = ap.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)

    if not RUN_EVAL.exists() or not METRICS.exists():
        print(f"[LOI] Khong thay {RUN_EVAL} hoac {METRICS} - chay script nay tu thu muc goc du an.",
              file=sys.stderr)
        sys.exit(1)

    ok = True
    if args.cmd == "e1":
        ok = cmd_e1(args)
    elif args.cmd == "e5":
        ok = cmd_e5(args)
    elif args.cmd == "e5-final":
        ok = cmd_e5_final(args)

    update_metrics(args)

    if not ok:
        print("\n[CANH BAO] Co it nhat 1 lenh con tra ve loi - xem log ben tren. "
              "Chay lai CUNG lenh run_matrix.py se tu dong resume (tung file --out van "
              "giu logic resumable cua run_eval.py).")
        sys.exit(1)
    print("\nXONG. Xem docs/figures/metrics_report.md de biet ket qua tong hop.")


if __name__ == "__main__":
    main()
