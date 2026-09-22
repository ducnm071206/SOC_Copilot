#!/usr/bin/env python3
"""
D3 [P0] Gan nhan theo giao thuc - phan TU LAM DUOC (khong can Duc/Binh).

Script nay KHONG tu gan nhan (do la viec cua Duc/Binh, sau khi SOP freeze).
No chi chuan bi "khung" de gan nhan:

  1. Lay mau PHAN TANG theo rule.id tu data/samples/manifest.csv (da duoc D2
     trich/sua/dedupe san), toi da --max-per-rule alert/rule (mac dinh 4,
     dung nhu checklist "toi da 3-4 alert moi rule"), muc tieu tong
     --target-min .. --target-max alert (mac dinh 60-100).
  2. Chia dev/test PHAN TANG theo rule, ti le ~50/50 (--dev-ratio).
  3. Chon ngau nhien ~25% mau (--kappa-ratio) de danh dau "second rater" -
     Binh se gan doc lap rieng cac dong nay de tinh do dong thuan/kappa.
  4. Xuat data/labels.csv - cac cot NHAN de TRONG cho Duc/Binh dien, cac cot
     THAM CHIEU (rule, level, mo ta, split...) dien san tu du lieu that.

QUAN TRONG: cot trong labels.csv duoc SUY DOAN hop ly tu ngu canh checklist
(vi Phu luc D - noi liet ke cot chinh thuc - KHONG duoc dinh kem cho script
nay). Truoc khi dua cho Duc/Binh dung that, HAY DOI CHIEU ten cot voi Phu luc
D that va sua lai --column-map hoac sua truc tiep header CSV neu can.

Usage:
    python3 eval/build_labeling_set.py \
        --manifest data/samples/manifest.csv \
        --out data/labels.csv \
        --max-per-rule 4 --target-min 60 --target-max 100 \
        --dev-ratio 0.5 --kappa-ratio 0.25 --seed 42
"""
from __future__ import annotations

import argparse
import csv
import random
from collections import defaultdict
from pathlib import Path

# Goi y thang do severity DANG KHOANG (khong phai so le), theo dung yeu cau
# checklist "dung khoang severity vi nhieu alert mo ho". Day la GOI Y, Duc/Binh
# co the dieu chinh khi thay Phu luc D that.
SEVERITY_RANGE_OPTIONS = [
    "1_thap (benign / scanner / false-positive ro rang)",
    "2_trung-thap (nghi ngo nhe, can theo doi)",
    "3_trung-binh (can xac minh chu dong, chua chac tan cong)",
    "4_trung-cao (kha nang cao la tan cong that, chua thanh cong ro rang)",
    "5_cao (tan cong that, co dau hieu thanh cong / anh huong he thong)",
]

RECOMMENDED_ACTION_OPTIONS = [
    "NO_ACTION",
    "MONITOR",
    "INVESTIGATE",
    "ESCALATE",
    "BLOCK_IP",
    "CONTAIN_HOST",
]

LABEL_COLUMNS_TO_FILL = [
    "assigned_severity_range",   # 1 trong SEVERITY_RANGE_OPTIONS
    "is_true_positive",          # yes / no / unsure - co phai tan cong that khong (vs scanner/FP)
    "recommended_action_label",  # 1 trong RECOMMENDED_ACTION_OPTIONS
    "labeler",                   # ten nguoi gan (Duc, hoac Binh cho kappa-check)
    "label_date",
    "notes",
]

REFERENCE_COLUMNS = [
    "alert_ref",        # duong dan file trong data/samples/
    "alert_id_raw",      # truong 'id' goc trong Wazuh alert (neu co)
    "rule_id",
    "rule_level",
    "rule_description",
    "source",           # raw_pool_sampled / raw_pool_verbatim_copy / curated_ai_or_manual / lab_synthetic
    "split",             # dev / test
    "is_kappa_check_sample",  # True/False - Binh gan doc lap neu True
    "rater2_label",           # Binh dien vao day (chi khi is_kappa_check_sample=True)
    "agreement_flag",         # dien SAU khi co ca 2 nhan: match/mismatch (tinh tay hoac bang script khac)
]


def load_manifest(path: Path) -> list[dict]:
    rows = []
    with path.open(encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if row.get("filename") == "(bo qua - trung lap)":
                continue
            if not row.get("filename"):
                continue
            rows.append(row)
    return rows


def stratified_cap(rows: list[dict], max_per_rule: int, rng: random.Random) -> list[dict]:
    by_rule = defaultdict(list)
    for r in rows:
        by_rule[r["rule_id"]].append(r)
    out = []
    for rid, group in by_rule.items():
        if len(group) <= max_per_rule:
            out.extend(group)
        else:
            out.extend(rng.sample(group, max_per_rule))
    return out


def stratified_dev_test_split(rows: list[dict], dev_ratio: float, rng: random.Random) -> dict[str, str]:
    """Tra ve {alert_ref: 'dev'|'test'}, chia phan tang theo rule.id."""
    by_rule = defaultdict(list)
    for r in rows:
        by_rule[r["rule_id"]].append(r)
    split_map = {}
    for rid, group in by_rule.items():
        shuffled = group[:]
        rng.shuffle(shuffled)
        n_dev = round(len(shuffled) * dev_ratio)
        # dam bao rule co >=2 mau thi ca dev va test deu co it nhat 1 (tranh rule
        # chi roi het vao 1 ben do lam tron)
        if len(shuffled) >= 2:
            n_dev = min(max(n_dev, 1), len(shuffled) - 1)
        for i, r in enumerate(shuffled):
            split_map[r["filename"]] = "dev" if i < n_dev else "test"
    return split_map


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--manifest", type=Path, default=Path("data/samples/manifest.csv"))
    ap.add_argument("--out", type=Path, default=Path("data/labels.csv"))
    ap.add_argument("--max-per-rule", type=int, default=4)
    ap.add_argument("--target-min", type=int, default=60)
    ap.add_argument("--target-max", type=int, default=100)
    ap.add_argument("--dev-ratio", type=float, default=0.5)
    ap.add_argument("--kappa-ratio", type=float, default=0.25)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    rng = random.Random(args.seed)

    if not args.manifest.exists():
        raise SystemExit(f"[LOI] Khong thay manifest: {args.manifest} - hay chay eval/extract_samples.py truoc.")

    rows = load_manifest(args.manifest)
    print(f"Doc {len(rows)} mau tu manifest ({args.manifest}).")

    capped = stratified_cap(rows, args.max_per_rule, rng)
    print(f"Sau khi gioi han toi da {args.max_per_rule} mau/rule: {len(capped)} mau, "
          f"{len(set(r['rule_id'] for r in capped))} rule.")

    if len(capped) < args.target_min:
        print(f"[CANH BAO] Tong so mau ({len(capped)}) THAP HON target-min ({args.target_min}). "
              "Co the can tang --max-per-rule, hoac bo sung them mau qua eval/extract_samples.py "
              "(vd tang --default-per-rule) truoc khi chay lai script nay.")
    elif len(capped) > args.target_max:
        excess = len(capped) - args.target_max
        print(f"[CANH BAO] Tong so mau ({len(capped)}) VUOT target-max ({args.target_max}) "
              f"({excess} mau thua). Dang cat bot ngau nhien (uu tien giu it nhat 1 mau/rule) "
              "de ve dung khoang muc tieu.")
        # cat bot: uu tien giu it nhat 1 mau/rule, cat tu cac rule dang co nhieu mau nhat truoc
        by_rule = defaultdict(list)
        for r in capped:
            by_rule[r["rule_id"]].append(r)
        rng.shuffle(capped)  # de viec cat khong thien vi thu tu file
        while sum(len(v) for v in by_rule.values()) > args.target_max:
            rid_max = max(by_rule, key=lambda k: len(by_rule[k]))
            if len(by_rule[rid_max]) <= 1:
                break  # khong cat xuong duoi 1 mau/rule nua
            by_rule[rid_max].pop()
        capped = [r for group in by_rule.values() for r in group]

    print(f"Tong so mau cuoi cung dua vao labels.csv: {len(capped)} "
          f"(muc tieu {args.target_min}-{args.target_max}).")

    split_map = stratified_dev_test_split(capped, args.dev_ratio, rng)
    n_dev = sum(1 for v in split_map.values() if v == "dev")
    n_test = len(split_map) - n_dev
    print(f"Chia dev/test (phan tang theo rule): dev={n_dev}, test={n_test}.")

    kappa_pool = capped[:]
    rng.shuffle(kappa_pool)
    n_kappa = round(len(kappa_pool) * args.kappa_ratio)
    kappa_files = set(r["filename"] for r in kappa_pool[:n_kappa])
    print(f"Danh dau {len(kappa_files)} mau ({args.kappa_ratio*100:.0f}%) de Binh gan doc lap (tinh kappa).")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = REFERENCE_COLUMNS + LABEL_COLUMNS_TO_FILL
    with args.out.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in sorted(capped, key=lambda x: (x["rule_id"], x["filename"])):
            writer.writerow({
                "alert_ref": f"data/samples/{r['filename']}",
                "alert_id_raw": "",  # co the dien sau tu file that neu can, de trong o day de gon
                "rule_id": r["rule_id"],
                "rule_level": r["level"],
                "rule_description": r["description"],
                "source": r["source"],
                "split": split_map.get(r["filename"], ""),
                "is_kappa_check_sample": r["filename"] in kappa_files,
                "rater2_label": "",
                "agreement_flag": "",
                "assigned_severity_range": "",
                "is_true_positive": "",
                "recommended_action_label": "",
                "labeler": "",
                "label_date": "",
                "notes": "",
            })

    # File huong dan kem theo, giai thich cac cot va gia tri hop le cho Duc/Binh
    guide_path = args.out.with_name("labels_README.md")
    guide_lines = [
        "# Huong dan dien data/labels.csv (D3)",
        "",
        "**Truoc khi Duc/Binh gan nhan**: SOP + prompt + nguong PHAI da freeze (tag `freeze-v1`). "
        "Nguoi gan nhan CHI duoc nhin file alert goc trong `alert_ref`, KHONG duoc nhin dau ra cua model.",
        "",
        f"- Tong so dong: se hien thi khi chay script (xem log chay).",
        f"- Cot da dien san (tham chieu, KHONG sua): {', '.join(REFERENCE_COLUMNS)}",
        f"- Cot Duc/Binh can dien: {', '.join(LABEL_COLUMNS_TO_FILL)}",
        "",
        "## assigned_severity_range - chon 1 trong cac khoang sau (co the dieu chinh neu Phu luc D quy dinh khac)",
        "",
    ]
    for opt in SEVERITY_RANGE_OPTIONS:
        guide_lines.append(f"- `{opt}`")
    guide_lines.append("")
    guide_lines.append("## recommended_action_label - chon 1 trong (co the dieu chinh theo SOP that)")
    guide_lines.append("")
    for opt in RECOMMENDED_ACTION_OPTIONS:
        guide_lines.append(f"- `{opt}`")
    guide_lines.append("")
    guide_lines.append("## is_true_positive")
    guide_lines.append("")
    guide_lines.append(
        "- `yes` / `no` / `unsure`. LUU Y dac biet: theo docs/data_provenance.md, phan lon alert rule "
        "31101/31151 (~85% pool) mang dau hieu la traffic quet Nikto tu dong, KHONG phai tan cong thu cong. "
        "Neu gap alert loai nay, hay xem xet gan `no` (hoac `unsure` neu khong chac) thay vi mac dinh `yes` "
        "chi vi rule co ten 'attack'."
    )
    guide_lines.append("")
    guide_lines.append("## is_kappa_check_sample")
    guide_lines.append("")
    guide_lines.append(
        "- Neu `True`: Binh PHAI gan nhan DOC LAP (khong xem nhan cua Duc truoc), dien vao `rater2_label` "
        "(dung cung dinh dang voi `assigned_severity_range` hoac `recommended_action_label` tuy quy uoc nhom "
        "chon). Sau khi ca hai co nhan, tinh % trung / Cohen's kappa va dien `agreement_flag`, roi hop thong "
        "nhat cac ca bat dong."
    )
    guide_lines.append("")
    guide_lines.append(
        "## Sau khi gan nhan xong: gan tag `freeze-v1` cho SOP/prompt/nguong + labels.csv nay, "
        "khong sua nguong/prompt tren tap `test` nua tu thoi diem do."
    )
    guide_path.write_text("\n".join(guide_lines), encoding="utf-8")

    print(f"Da ghi: {args.out}")
    print(f"Huong dan: {guide_path}")


if __name__ == "__main__":
    main()
