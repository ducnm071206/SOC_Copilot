#!/usr/bin/env python3
"""
D6 [P0] Bao cao ket qua - eval/report.py

Doc docs/figures/metrics_report.json (san pham cua eval/metrics.py), sinh:
    - Bieu do (matplotlib) vao docs/figures/*.png
    - eval/REPORT.md tom tat: bang so sanh cac to hop (model, mode), do tre,
      va PHAN TICH 10 CA SAI NANG NHAT kem goi y nguyen nhan goc (truy xuat
      sai / model sai / SOP thieu / nhan sai) - goi y TU DONG, con nguoi PHAI
      xem lai truoc khi dua vao bao cao chinh thuc.

Neu chua co nhan that (data/labels.csv con trong), script van chay duoc,
KHONG crash, chi bao ro "chua co du lieu de phan tich" thay vi bia so lieu.

KET QUA AM TINH (vd RAG khong hon rule_map) VAN duoc viet trung thuc vao
REPORT.md, khong bi loai bo hay lam mo di.

Usage:
    python3 eval/report.py \
        --metrics-json docs/figures/metrics_report.json \
        --out-md eval/REPORT.md \
        --figures-dir docs/figures
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

import matplotlib
matplotlib.use("Agg")  # khong can man hinh, chi xuat file
import matplotlib.pyplot as plt


def load_metrics(path: Path) -> dict:
    if not path.exists():
        raise SystemExit(f"[LOI] Khong thay {path}. Chay eval/metrics.py truoc.")
    return json.loads(path.read_text(encoding="utf-8"))


def guess_root_cause(mismatch: dict, source_by_ref: dict[str, str]) -> str:
    """Goi y (heuristic, KHONG chac chan) nguyen nhan goc cho 1 ca sai, de nguoi
    doc de bat dau phan loai - PHAI xem lai thu cong, khong duoc tin tuyet doi."""
    ref = mismatch.get("alert_ref", "")
    mode = mismatch.get("mode", "")
    source = source_by_ref.get(ref, "")
    tags = []
    if source == "lab_synthetic":
        tags.append("SOP THIEU (co the) - alert nay la du lieu lab tong hop cho SOP con thieu quy dinh ro rang")
    if mode == "none":
        tags.append("TRUY XUAT SAI (rat co the) - mode 'none' khong co ngu canh SOP nao ca")
    if "adversarial" in ref or any(k in ref for k in ("prompt_injection", "wrapped", "non_wazuh", "missing", "long")):
        tags.append("CA ADVERSARIAL - kiem tra rieng, khong tinh chung voi loi 'binh thuong'")
    field = mismatch.get("field")
    if field == "severity_range" and mismatch.get("lech_bac", 0) == 1:
        tags.append("NHAN MO HO (co the) - lech dung 1 bac, co the la ranh gioi giua 2 khoang severity")
    if not tags:
        tags.append("CAN XEM THU CONG - khong co dau hieu tu dong ro rang (co the la MODEL SAI hoac NHAN SAI)")
    return "; ".join(tags)


def make_charts(metrics: dict, figures_dir: Path) -> list[str]:
    figures_dir.mkdir(parents=True, exist_ok=True)
    written = []
    by_group = metrics.get("by_model_mode", {})
    if not by_group:
        return written

    # --- Bieu do do chinh xac theo (model, mode) - CHI ve neu co it nhat 1 nhom co n>0 ---
    metric_names = ["recommended_action_accuracy", "is_true_positive_accuracy",
                     "severity_exact_match", "severity_within_1_bucket"]
    labels_vi = {
        "recommended_action_accuracy": "Do khop hanh dong",
        "is_true_positive_accuracy": "Do khop TP/FP",
        "severity_exact_match": "Severity (khop dung)",
        "severity_within_1_bucket": "Severity (lech <=1 bac)",
    }
    any_data = any(
        by_group[g][m]["n"] > 0 for g in by_group for m in metric_names if m in by_group[g]
    )
    if any_data:
        groups = sorted(by_group.keys())
        x = range(len(groups))
        fig, ax = plt.subplots(figsize=(max(6, len(groups) * 1.8), 5))
        width = 0.2
        for i, m in enumerate(metric_names):
            vals = []
            for g in groups:
                entry = by_group[g].get(m, {"k": 0, "n": 0})
                vals.append(entry["k"] / entry["n"] if entry["n"] > 0 else 0)
            offset = (i - len(metric_names) / 2) * width + width / 2
            ax.bar([xi + offset for xi in x], vals, width, label=labels_vi[m])
        ax.set_xticks(list(x))
        ax.set_xticklabels(groups, rotation=20, ha="right")
        ax.set_ylabel("Ty le dung (k/n)")
        ax.set_ylim(0, 1.05)
        ax.set_title("Do chinh xac theo tung to hop (model|mode)", fontsize=11)
        fig.text(0.5, 0.965, "Mau nho - xem CI Wilson trong metrics_report.md, khong doc nhu ty le tuyet doi",
                  ha="center", fontsize=8, style="italic")
        ax.legend(fontsize=8)
        fig.tight_layout(rect=(0, 0, 1, 0.93))
        out = figures_dir / "accuracy_by_group.png"
        fig.savefig(out, dpi=120)
        plt.close(fig)
        written.append(str(out))
    else:
        # ve 1 bieu do "khong co du lieu" de bao cao khong bi thieu hinh mot cach kho hieu
        fig, ax = plt.subplots(figsize=(6, 3))
        ax.text(0.5, 0.5, "Chua co nhan that trong data/labels.csv\n(0/0 cho tat ca metric)",
                ha="center", va="center", fontsize=12)
        ax.axis("off")
        out = figures_dir / "accuracy_by_group.png"
        fig.savefig(out, dpi=120)
        plt.close(fig)
        written.append(str(out))

    # --- Bieu do do tre theo (model, mode) ---
    lat_rows = []  # (group, mean, p95)
    for g, m in sorted(by_group.items()):
        for key, stats in m.get("latency_by_model_mode", {}).items():
            lat_rows.append((key, stats["mean_seconds"], stats["p95_seconds"]))
    if lat_rows:
        fig, ax = plt.subplots(figsize=(max(6, len(lat_rows) * 1.5), 5))
        x = range(len(lat_rows))
        ax.bar([xi - 0.15 for xi in x], [r[1] for r in lat_rows], width=0.3, label="mean")
        ax.bar([xi + 0.15 for xi in x], [r[2] for r in lat_rows], width=0.3, label="p95")
        ax.set_xticks(list(x))
        ax.set_xticklabels([r[0] for r in lat_rows], rotation=20, ha="right")
        ax.set_ylabel("Giay")
        ax.set_title("Do tre theo to hop (model|mode) - DA LOAI cold-start")
        ax.legend()
        fig.tight_layout()
        out = figures_dir / "latency_by_group.png"
        fig.savefig(out, dpi=120)
        plt.close(fig)
        written.append(str(out))

    return written


def collect_top_mismatches(metrics: dict, source_by_ref: dict[str, str], top_n: int = 10) -> list[dict]:
    all_mismatches = []
    for group, m in metrics.get("by_model_mode", {}).items():
        for mm in m.get("mismatches", []):
            mm = dict(mm)
            mm["group"] = group
            all_mismatches.append(mm)

    def severity_key(mm):
        if mm.get("field") == "severity_range":
            return mm.get("lech_bac", 1)
        return 2  # sai hanh dong / sai TP-FP coi nhu "nang" tuong duong lech 2 bac

    all_mismatches.sort(key=severity_key, reverse=True)
    top = all_mismatches[:top_n]
    for mm in top:
        mm["goi_y_nguyen_nhan"] = guess_root_cause(mm, source_by_ref)
    return top


def load_source_map(manifest_path: Path) -> dict[str, str]:
    """Doc data/samples/manifest.csv -> {filename: source} de biet mau nao la
    lab_synthetic/curated/raw_pool khi phan tich nguyen nhan sai."""
    out = {}
    if not manifest_path.exists():
        return out
    import csv
    with manifest_path.open(encoding="utf-8") as f:
        for row in csv.DictReader(f):
            fn = row.get("filename")
            if fn and fn != "(bo qua - trung lap)":
                out[f"data/samples/{fn}"] = row.get("source", "")
    return out


def render_report_md(metrics: dict, chart_paths: list[str], top_mismatches: list[dict]) -> str:
    overall = metrics.get("overall", {})
    by_group = metrics.get("by_model_mode", {})
    lines = []
    lines.append("# eval/REPORT.md - Bao cao ket qua danh gia (D6)")
    lines.append("")
    lines.append(
        "**Nhac lai nguyen tac bao cao (checklist D4/D6)**: du lieu tu MOT lab, mau nho -> "
        "moi con so bao cao dang k/n kem khoang tin cay Wilson (xem `docs/figures/metrics_report.md`), "
        "KHONG khai quat ra ngoai pham vi du lieu nay. Ket qua AM TINH (vd mode nao do khong tot hon "
        "mode khac) VAN duoc bao cao trung thuc ben duoi, khong bi bo qua."
    )
    lines.append("")

    n_labeled = overall.get("n_matched_with_ground_truth", 0)
    if n_labeled == 0:
        lines.append(
            "> ## ⚠️ CHUA CO NHAN THAT\n"
            "> `data/labels.csv` hien chua co dong nao duoc Duc/Binh gan nhan, nen TOAN BO metric ben "
            "duoi deu la `0/0`. Day la trang thai DUNG (khong bia so), khong phai loi. File nay se TU "
            "DONG co so lieu that khi chay lai (`python3 eval/metrics.py ... && python3 eval/report.py ...`) "
            "sau khi lao dong gan nhan (D3, phan phu thuoc nguoi khac) hoan tat."
        )
        lines.append("")

    lines.append("## Bieu do")
    lines.append("")
    for p in chart_paths:
        rel = Path(p).name
        lines.append(f"![{rel}](figures/{rel})" if not p.startswith("docs/") else f"![{rel}]({p.replace('docs/', '', 1)})")
    lines.append("")

    lines.append("## Bang tong hop theo to hop (model, mode)")
    lines.append("")
    lines.append("| model\\|mode | tong dong | loi/khong parse | khop hanh dong | khop TP/FP | severity dung | severity lech<=1 |")
    lines.append("|---|---:|---:|---|---|---|---|")
    for g, m in sorted(by_group.items()):
        lines.append(
            f"| {g} | {m['n_total_records']} | {m['n_error_or_no_parse']} | "
            f"{m['recommended_action_accuracy']['display']} | {m['is_true_positive_accuracy']['display']} | "
            f"{m['severity_exact_match']['display']} | {m['severity_within_1_bucket']['display']} |"
        )
    lines.append("")

    lines.append("## 10 ca sai nang nhat + goi y nguyen nhan goc")
    lines.append("")
    lines.append(
        "Goi y nguyen nhan duoi day la HEURISTIC TU DONG (dua tren mode, nguon du lieu, do lech severity) "
        "- **PHAI xem lai tung ca thu cong** truoc khi ket luan chinh thuc. 4 nhom nguyen nhan theo "
        "checklist: **truy xuat sai** (retrieval dua sai/thieu ngu canh SOP), **model sai** (co du ngu canh "
        "nhung model van suy luan/tra loi sai), **SOP thieu** (SOP goc khong co huong dan ro cho tinh huong "
        "nay), **nhan sai** (nguoi gan nhan co the nham, dac biet voi cac alert mo ho o ranh gioi severity)."
    )
    lines.append("")
    if not top_mismatches:
        lines.append(
            "_Chua co ca sai nao de phan tich (chua co nhan that - xem canh bao o dau file). "
            "Muc nay se tu dong dien khi chay lai script sau khi co nhan._"
        )
    else:
        lines.append("| # | to hop | alert_ref | truong sai | model tra loi | nhan that | goi y nguyen nhan |")
        lines.append("|---|---|---|---|---|---|---|")
        for i, mm in enumerate(top_mismatches, start=1):
            lines.append(
                f"| {i} | {mm.get('group')} | {mm.get('alert_ref')} | {mm.get('field')} | "
                f"`{mm.get('predicted')}` | `{mm.get('ground_truth')}` | {mm.get('goi_y_nguyen_nhan')} |"
            )
    lines.append("")

    lines.append("## Do tre")
    lines.append("")
    lines.append("Xem bang chi tiet (mean/median/p95, da loai cold-start) trong `docs/figures/metrics_report.md`.")
    lines.append("")

    lines.append("## Ket luan tam thoi")
    lines.append("")
    if n_labeled == 0:
        lines.append(
            "_Chua the ket luan gi ve do chinh xac vi chua co nhan that. Sau khi Duc/Binh gan nhan xong "
            "(D3 phan phu thuoc) va chay lai pipeline, dien phan nay bang tay dua tren so lieu that, "
            "kem ca ket qua am tinh neu co (vd 'RAG khong cho thay cai thien ro ret so voi rule_map "
            "trong du lieu nay')._"
        )
    else:
        lines.append("_(Dien tay sau khi xem bang tong hop o tren - neu ket qua am tinh, viet ro rang, "
                      "khong loai bo.)_")
    lines.append("")
    lines.append("---")
    lines.append("_Sinh boi `eval/report.py`. Doi chieu voi `docs/figures/metrics_report.md` (JSON: "
                  "`docs/figures/metrics_report.json`) de xem chi tiet day du hon._")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--metrics-json", type=Path, default=Path("docs/figures/metrics_report.json"))
    ap.add_argument("--manifest", type=Path, default=Path("data/samples/manifest.csv"))
    ap.add_argument("--out-md", type=Path, default=Path("eval/REPORT.md"))
    ap.add_argument("--figures-dir", type=Path, default=Path("docs/figures"))
    ap.add_argument("--top-n", type=int, default=10)
    args = ap.parse_args()

    metrics = load_metrics(args.metrics_json)
    source_by_ref = load_source_map(args.manifest)

    chart_paths = make_charts(metrics, args.figures_dir)
    print(f"Da ve {len(chart_paths)} bieu do: {chart_paths}")

    top_mismatches = collect_top_mismatches(metrics, source_by_ref, top_n=args.top_n)
    print(f"Thu thap {len(top_mismatches)} ca sai (toi da {args.top_n}) de phan tich.")

    md = render_report_md(metrics, chart_paths, top_mismatches)
    args.out_md.parent.mkdir(parents=True, exist_ok=True)
    args.out_md.write_text(md, encoding="utf-8")
    print(f"Da ghi: {args.out_md}")


if __name__ == "__main__":
    main()
