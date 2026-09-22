#!/usr/bin/env python3
"""
D4 [P0] eval/metrics.py

Doc ket qua tu eval/run_eval.py (1 hoac nhieu file JSONL) + data/labels.csv
(nhan nguoi that), tinh cac metric va IN RA DUNG DINH DANG checklist yeu cau:

    "Vi n nho, bao cao dang k/n kem khoang tin cay Wilson; KHONG noi kieu
    'chinh xac 93,4%' va KHONG khai quat ra ngoai du lieu mot lab."

Metric tinh (khi co nhan that trong labels.csv):
    - Do khop recommended_action (dung/tong, Wilson CI)
    - Do khop is_true_positive (dung/tong, Wilson CI)
    - Do khop severity: KHOP CHINH XAC va KHOP TRONG PHAM VI 1 BAC (vi checklist
      D3 noi "dung khoang severity vi nhieu alert mo ho" - lech 1 bac lien ke
      it nghiem trong hon lech nhieu bac)
    - Ty le output khong parse duoc JSON (loi model, khong phai loi nhan)
    - Do tre: mean/median/p95, LOAI BO call_index_in_run==1 (cold start) cho
      tung to hop (model, mode) nhu checklist yeu cau

Neu labels.csv CHUA DUOC GAN NHAN (assigned_severity_range/recommended_action_label/
is_true_positive con rong - truong hop THU 2 truoc khi Duc/Binh gan xong), script
VAN CHAY duoc nhung bao n=0 ro rang cho cac metric can nhan, KHONG crash, KHONG
bia so - chi in duoc phan do tre (khong can nhan).

Usage:
    python3 eval/metrics.py \
        --results data/eval_runs/*.jsonl \
        --labels data/labels.csv \
        --out-md docs/figures/metrics_report.md \
        --out-json docs/figures/metrics_report.json
"""
from __future__ import annotations

import argparse
import csv
import glob
import json
import math
import statistics
from collections import defaultdict
from pathlib import Path


def wilson_ci(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """Khoang tin cay Wilson score cho ty le k/n (mac dinh 95%, z=1.96).
    Tra ve (low, high) trong [0,1]. Neu n=0, tra ve (0.0, 1.0) (khong biet gi)."""
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    denom = 1 + z * z / n
    center = p + z * z / (2 * n)
    margin = z * math.sqrt((p * (1 - p) + z * z / (4 * n)) / n)
    low = (center - margin) / denom
    high = (center + margin) / denom
    return (max(0.0, low), min(1.0, high))


def fmt_kn(k: int, n: int) -> str:
    if n == 0:
        return "0/0 (khong co du lieu)"
    low, high = wilson_ci(k, n)
    return f"{k}/{n} (95% CI Wilson: {low*100:.0f}%-{high*100:.0f}%)"


def load_labels(path: Path) -> dict[str, dict]:
    """key = alert_ref (duong dan trong labels.csv, khop voi alert_ref trong ket qua run_eval)."""
    by_ref = {}
    if not path.exists():
        return by_ref
    with path.open(encoding="utf-8") as f:
        for row in csv.DictReader(f):
            by_ref[row["alert_ref"]] = row
    return by_ref


def load_results(patterns: list[str]) -> list[dict]:
    paths = []
    for pat in patterns:
        paths.extend(glob.glob(pat))
    paths = sorted(set(paths))
    records = []
    for p in paths:
        with open(p, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return records, paths


def severity_bucket_index(value: str) -> int | None:
    """Chuyen chuoi kieu '3_trung-binh' hoac '3' thanh so nguyen 1..5 de so sanh
    'lech bao nhieu bac'. Tra ve None neu khong doc duoc."""
    if not value:
        return None
    value = str(value).strip()
    lead = value.split("_")[0]
    try:
        n = int(lead)
        if 1 <= n <= 5:
            return n
    except ValueError:
        pass
    return None


def compute_group_metrics(records: list[dict], labels: dict[str, dict]) -> dict:
    n_total = len(records)
    n_error_no_parse = sum(1 for r in records if r.get("error"))
    n_matched_label = 0

    action_k = action_n = 0
    tp_k = tp_n = 0
    sev_exact_k = sev_exact_n = 0
    sev_within1_k = sev_within1_n = 0

    mismatches = []  # de D6 phan tich 10 ca sai nang nhat

    for r in records:
        if r.get("error"):
            continue
        label = labels.get(r.get("alert_ref"))
        if not label:
            continue
        parsed = r.get("parsed_output") or {}

        gt_action = (label.get("recommended_action_label") or "").strip()
        gt_tp = (label.get("is_true_positive") or "").strip().lower()
        gt_sev = (label.get("assigned_severity_range") or "").strip()

        has_any_label = gt_action or gt_tp or gt_sev
        if not has_any_label:
            continue
        n_matched_label += 1

        if gt_action:
            pred_action = str(parsed.get("recommended_action", "")).strip()
            action_n += 1
            ok = pred_action == gt_action
            action_k += int(ok)
            if not ok:
                mismatches.append({
                    "alert_ref": r.get("alert_ref"), "field": "recommended_action",
                    "predicted": pred_action, "ground_truth": gt_action,
                    "model": r.get("model"), "mode": r.get("mode"),
                })

        if gt_tp:
            pred_tp = str(parsed.get("is_true_positive", "")).strip().lower()
            tp_n += 1
            ok = pred_tp == gt_tp
            tp_k += int(ok)
            if not ok:
                mismatches.append({
                    "alert_ref": r.get("alert_ref"), "field": "is_true_positive",
                    "predicted": pred_tp, "ground_truth": gt_tp,
                    "model": r.get("model"), "mode": r.get("mode"),
                })

        if gt_sev:
            pred_sev = str(parsed.get("severity_range", "")).strip()
            gt_idx = severity_bucket_index(gt_sev)
            pred_idx = severity_bucket_index(pred_sev)
            if gt_idx is not None and pred_idx is not None:
                sev_exact_n += 1
                exact_ok = pred_idx == gt_idx
                sev_exact_k += int(exact_ok)
                sev_within1_n += 1
                within1_ok = abs(pred_idx - gt_idx) <= 1
                sev_within1_k += int(within1_ok)
                if not exact_ok:
                    mismatches.append({
                        "alert_ref": r.get("alert_ref"), "field": "severity_range",
                        "predicted": pred_sev, "ground_truth": gt_sev,
                        "lech_bac": abs(pred_idx - gt_idx),
                        "model": r.get("model"), "mode": r.get("mode"),
                    })

    # do tre: loai cold start (call_index_in_run == 1) cho tung (model,mode)
    latencies_by_group = defaultdict(list)
    latencies_all_incl_cold = defaultdict(list)
    for r in records:
        if r.get("error") or r.get("latency_seconds") is None:
            continue
        key = (r.get("model"), r.get("mode"))
        latencies_all_incl_cold[key].append(r["latency_seconds"])
        if r.get("call_index_in_run") != 1:
            latencies_by_group[key].append(r["latency_seconds"])

    latency_stats = {}
    for key, vals in latencies_by_group.items():
        if not vals:
            continue
        vals_sorted = sorted(vals)
        p95_idx = min(len(vals_sorted) - 1, int(round(0.95 * (len(vals_sorted) - 1))))
        latency_stats[f"{key[0]}|{key[1]}"] = {
            "n_excl_cold_start": len(vals),
            "n_incl_cold_start": len(latencies_all_incl_cold[key]),
            "mean_seconds": round(statistics.mean(vals), 3),
            "median_seconds": round(statistics.median(vals), 3),
            "p95_seconds": round(vals_sorted[p95_idx], 3),
            "min_seconds": round(min(vals), 3),
            "max_seconds": round(max(vals), 3),
        }

    return {
        "n_total_records": n_total,
        "n_error_or_no_parse": n_error_no_parse,
        "n_matched_with_ground_truth": n_matched_label,
        "recommended_action_accuracy": {"k": action_k, "n": action_n, "display": fmt_kn(action_k, action_n)},
        "is_true_positive_accuracy": {"k": tp_k, "n": tp_n, "display": fmt_kn(tp_k, tp_n)},
        "severity_exact_match": {"k": sev_exact_k, "n": sev_exact_n, "display": fmt_kn(sev_exact_k, sev_exact_n)},
        "severity_within_1_bucket": {"k": sev_within1_k, "n": sev_within1_n, "display": fmt_kn(sev_within1_k, sev_within1_n)},
        "latency_by_model_mode": latency_stats,
        "mismatches": mismatches,
    }


def render_markdown(overall: dict, by_group: dict[str, dict], n_labels_available: int) -> str:
    lines = []
    lines.append("# Bao cao metric (D4/D6 so bo)")
    lines.append("")
    lines.append(
        "**CANH BAO BAT BUOC** (checklist D4): vi co mau nho, moi con so duoi day duoc bao cao dang "
        "`k/n` kem khoang tin cay Wilson 95%, KHONG duoc doc/trich dan nhu ty le phan tram chinh xac "
        "tuyet doi (vd khong noi 'model dat 93,4% chinh xac'). KET QUA CHI PHAN ANH DU LIEU CUA 1 LAB "
        "NAY, KHONG duoc khai quat ra ngoai pham vi du lieu da thu thap."
    )
    lines.append("")
    if n_labels_available == 0:
        lines.append(
            "> **LUU Y**: `data/labels.csv` hien CHUA CO nhan nao duoc dien (Duc/Binh chua gan nhan). "
            "Cac metric can nhan (recommended_action, is_true_positive, severity) deu hien thi `0/0` "
            "duoi day - day la HANH VI DUNG (khong bia so), khong phai loi. Sau khi co nhan that, "
            "chay lai script nay."
        )
        lines.append("")

    lines.append("## Tong quan tat ca ket qua da nap")
    lines.append("")
    lines.append(f"- Tong so dong ket qua (moi to hop model/mode/run): {overall['n_total_records']}")
    lines.append(f"- Loi hoac khong parse duoc JSON: {overall['n_error_or_no_parse']}")
    lines.append(f"- Khop duoc voi it nhat 1 nhan that trong labels.csv: {overall['n_matched_with_ground_truth']}")
    lines.append("")

    lines.append("## Ket qua theo tung to hop (model, mode)")
    lines.append("")
    lines.append("| model | mode | recommended_action | is_true_positive | severity (khop dung) | severity (lech <=1 bac) |")
    lines.append("|---|---|---|---|---|---|")
    for key, m in sorted(by_group.items()):
        model, mode = key.split("|", 1)
        lines.append(
            f"| {model} | {mode} | {m['recommended_action_accuracy']['display']} | "
            f"{m['is_true_positive_accuracy']['display']} | {m['severity_exact_match']['display']} | "
            f"{m['severity_within_1_bucket']['display']} |"
        )
    lines.append("")

    lines.append("## Do tre (giay) - DA LOAI BO lan goi dau tien/cold-start cho tung (model, mode)")
    lines.append("")
    lines.append("| model | mode | n (loai cold-start) | n (goc, gom cold-start) | mean | median | p95 |")
    lines.append("|---|---|---:|---:|---:|---:|---:|")
    for key, m in sorted(by_group.items()):
        model, mode = key.split("|", 1)
        for lat_key, stats in m["latency_by_model_mode"].items():
            lines.append(
                f"| {model} | {mode} | {stats['n_excl_cold_start']} | {stats['n_incl_cold_start']} | "
                f"{stats['mean_seconds']}s | {stats['median_seconds']}s | {stats['p95_seconds']}s |"
            )
    lines.append("")

    lines.append("## Ca sai (mismatches) - de D6 phan tich 10 ca sai nang nhat")
    lines.append("")
    total_mismatches = sum(len(m["mismatches"]) for m in by_group.values())
    lines.append(f"- Tong so ca sai (tren tat ca truong/to hop): {total_mismatches}")
    lines.append(
        "- Chi tiet tung ca nam trong `docs/figures/metrics_report.json` (khoa `mismatches` trong tung "
        "to hop model/mode) - dung file JSON de loc/sap xep khi viet D6."
    )
    lines.append("")
    lines.append("---")
    lines.append(
        "_Sinh boi `eval/metrics.py`. Ket qua am tinh (vd mode nao do KHONG tot hon mode khac) van la "
        "ket qua hop le va PHAI duoc bao cao trung thuc, khong chi bao cao ket qua co loi._"
    )
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--results", nargs="+", required=True,
                     help="1 hoac nhieu duong dan/glob pattern toi file JSONL cua eval/run_eval.py, "
                          "vd data/eval_runs/*.jsonl")
    ap.add_argument("--labels", type=Path, default=Path("data/labels.csv"))
    ap.add_argument("--out-md", type=Path, default=Path("docs/figures/metrics_report.md"))
    ap.add_argument("--out-json", type=Path, default=Path("docs/figures/metrics_report.json"))
    args = ap.parse_args()

    labels = load_labels(args.labels)
    n_labels_available = sum(
        1 for row in labels.values()
        if (row.get("recommended_action_label") or row.get("is_true_positive") or row.get("assigned_severity_range"))
    )
    print(f"Doc {len(labels)} dong tu {args.labels} ({n_labels_available} dong da co it nhat 1 nhan dien).")

    records, paths = load_results(args.results)
    print(f"Doc {len(records)} dong ket qua tu {len(paths)} file: {paths}")

    if not records:
        print("[CANH BAO] Khong doc duoc dong ket qua nao - kiem tra lai --results co dung duong dan khong.")

    overall = compute_group_metrics(records, labels)

    by_group = defaultdict(list)
    for r in records:
        by_group[(r.get("model"), r.get("mode"))].append(r)
    group_metrics = {
        f"{k[0]}|{k[1]}": compute_group_metrics(v, labels) for k, v in by_group.items()
    }

    args.out_md.parent.mkdir(parents=True, exist_ok=True)
    args.out_json.parent.mkdir(parents=True, exist_ok=True)

    md = render_markdown(overall, group_metrics, n_labels_available)
    args.out_md.write_text(md, encoding="utf-8")
    args.out_json.write_text(
        json.dumps({"overall": overall, "by_model_mode": group_metrics}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    print(f"Da ghi: {args.out_md}")
    print(f"Da ghi: {args.out_json}")


if __name__ == "__main__":
    main()
