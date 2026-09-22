#!/usr/bin/env python3
"""
D2 [P0] Dung lai tap mau bang script.

Lam 3 viec, tat ca co seed (khong copy tay):

1. Trich mau moi tu tap alert goc (data/raw/alerts_temp.json) theo rule.id,
   uu tien cac rule ma D2 yeu cau bo sung (31103, 31105, 550, 40112, 31168, 510)
   va lay them mot so mau cho cac rule khac de co du lieu doi chieu.
2. Doc lai cac file "mauN..." da co san (thu cong / AI viet truoc do), LAY
   rule.id THAT trong noi dung file (khong tin ten file) de dat ten lai
   dung chuan <ruleid>_<n>.json, vi nhieu ten file cu bi lech rule
   (vi du mau4_sqli_31101.json nhung noi dung thuc te la rule 31106).
3. Kiem tra loi da biet:
   - Trung lap hoan toan (sha256 toan bo record).
   - Hai mau co data giong het nhau nhung khac nhau ve su co mat cua 'url'
     (dau hieu "trung vi thieu url").
   - Mau co ten/nhan goi y sai voi noi dung that (vd "portscan" nhung la
     web 404, "privilege escalation" nhung la first-time-sudo level thap).
   - Rule ma tap alert goc KHONG CO alert that nao (vd portscan, privilege
     escalation that su) -> ghi ro de nhom quyet dinh phuong an (a)/(b).

Ket qua:
    data/samples/<ruleid>_<n>.json        - tung alert, 1 file/alert
    data/samples/manifest.csv             - bang tra cuu + ghi chu loi/nhan goi y
    data/samples/extraction_report.md     - bao cao doi chieu voi checklist D2

Usage:
    python3 eval/extract_samples.py \
        --raw-pool data/raw/alerts_temp.json \
        --curated-dir data/samples_curated_original \
        --out-dir data/samples \
        --seed 42
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import random
import sys
from collections import defaultdict
from pathlib import Path

# Cac rule ma D2 yeu cau ro rang phai co mat trong tap mau, kem so luong toi da
# muon lay tu pool that va ghi chu tu checklist goc.
REQUIRED_RULES = {
    "31103": {"max_n": 2, "note": "SQLi - checklist D2 yeu cau bo sung"},
    "31105": {"max_n": 3, "note": "XSS - checklist D2 yeu cau bo sung"},
    "550": {"max_n": 3, "note": "Integrity checksum changed - checklist yeu cau tren duong dan LANH TINH; "
                                  "PHAI KIEM TRA THU CONG path/uid/gname truoc khi gan nhan, script khong tu suy ra lanh tinh hay khong"},
    "40112": {"max_n": 2, "note": "Multiple auth failures followed by success (level 12) - checklist yeu cau bo sung"},
    "31168": {"max_n": 3, "note": "Shellshock attack detected (level 15) - checklist yeu cau bo sung"},
    "510": {"max_n": 3, "note": "NGHI FALSE POSITIVE cua rootcheck - XAC MINH THU CONG TRUOC KHI GAN NHAN, "
                                  "khong duoc gan nhan tu dong"},
}

# Rule ma checklist da chi ra la CO THE khong co alert that (portscan / priv esc).
# Dung de doi chieu: neu script thay pool that co du lieu roi thi phai canh bao
# nguoi dung cap nhat lai checklist, vi gia dinh cu co the da sai.
KNOWN_POSSIBLY_MISSING_IN_RAW = {
    "100200": "Port scan (SOP)",
    "5407": "Privilege escalation (SOP) - LUU Y: 5407 khong phai ma rule Wazuh chuan tung thay; "
             "kiem tra xem co phai nham voi 5402/5403 khong",
}


def sha256_of(obj) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()


def load_ndjson(path: Path) -> list[dict]:
    records = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return records


def index_by_rule(records: list[dict]) -> dict[str, list[dict]]:
    idx = defaultdict(list)
    for d in records:
        rid = (d.get("rule", {}) or {}).get("id", "UNKNOWN")
        idx[rid].append(d)
    return idx


def data_key_ignoring_url(data: dict | None) -> str:
    """Chu ky cua truong 'data' NEU bo qua truong 'url' - dung de phat hien
    hai alert de bi coi la 'giong het nhau' chi vi thieu url. Dung JSON string
    lam key de an toan voi gia tri long nhau (vd truong 'audit' la mot dict)."""
    if not data:
        return ""
    filtered = {k: v for k, v in data.items() if k != "url"}
    if not filtered:
        return ""
    return json.dumps(filtered, sort_keys=True, ensure_ascii=False)


def detect_missing_url_lookalikes(entries: list[dict]) -> list[tuple[str, str]]:
    """entries: list of {'filename':..., 'record':...}. Tra ve cac cap filename
    ma data giong het nhau (tru url) nhung mot ben co url, mot ben thieu/rong."""
    buckets = defaultdict(list)
    for e in entries:
        data = e["record"].get("data")
        key = data_key_ignoring_url(data)
        if key:
            buckets[key].append(e)
    pairs = []
    for key, group in buckets.items():
        if len(group) < 2:
            continue
        urls = [(e["filename"], (e["record"].get("data") or {}).get("url")) for e in group]
        has_url = [u for u in urls if u[1]]
        no_url = [u for u in urls if not u[1]]
        if has_url and no_url:
            for a in has_url:
                for b in no_url:
                    pairs.append((a[0], b[0]))
    return pairs


def sample_for_rule(pool: list[dict], rule_id: str, n: int, rng: random.Random) -> list[dict]:
    if not pool:
        return []
    if len(pool) <= n:
        return list(pool)
    return rng.sample(pool, n)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--raw-pool", type=Path, default=Path("data/raw/alerts_temp.json"))
    ap.add_argument("--curated-dir", type=Path, default=Path("data/samples_curated_original"),
                     help="Thu muc chua cac file mauN*.json da co san truoc do")
    ap.add_argument("--out-dir", type=Path, default=Path("data/samples"))
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--default-per-rule", type=int, default=2,
                     help="So mau lay tu pool that cho cac rule KHONG nam trong REQUIRED_RULES "
                          "(de co du lieu doi chieu / da dang, khong bat buoc theo checklist D2)")
    args = ap.parse_args()

    rng = random.Random(args.seed)

    if not args.raw_pool.exists():
        print(f"[LOI] Khong thay raw pool: {args.raw_pool}", file=sys.stderr)
        sys.exit(1)

    records = load_ndjson(args.raw_pool)
    by_rule = index_by_rule(records)
    print(f"Da doc {len(records)} alert tu pool, {len(by_rule)} rule.id khac nhau.")

    # Bang tra cuu sha256(toan bo record) -> id goc, de biet mot file curated
    # co phai la BAN COPY NGUYEN VAN tu pool that hay khong (khong phu thuoc
    # vao viec pool co duoc lay mau trung vao no hay khong).
    raw_hash_to_id = {sha256_of(rec): rec.get("id") for rec in records}

    args.out_dir.mkdir(parents=True, exist_ok=True)

    manifest_rows = []
    written_hashes: dict[str, str] = {}  # sha256(full record) -> filename da ghi
    all_entries_for_url_check = []  # {'filename':, 'record':}

    def write_sample(record: dict, filename: str, source: str, notes: list[str],
                      needs_manual_verification: bool = False, suggested_label_hint: str = "",
                      original_filename: str = ""):
        h = sha256_of(record)
        if h in written_hashes:
            notes.append(f"BO QUA - trung lap hoan toan (sha256) voi {written_hashes[h]}")
            manifest_rows.append({
                "filename": "(bo qua - trung lap)",
                "rule_id": (record.get("rule", {}) or {}).get("id"),
                "level": (record.get("rule", {}) or {}).get("level"),
                "description": (record.get("rule", {}) or {}).get("description"),
                "source": source,
                "original_filename": original_filename,
                "sha256_full_log": hashlib.sha256((record.get("full_log", "") or "").encode()).hexdigest()[:16],
                "needs_manual_verification": needs_manual_verification,
                "suggested_label_hint": suggested_label_hint,
                "notes": "; ".join(notes),
            })
            return None
        written_hashes[h] = filename
        out_path = args.out_dir / filename
        out_path.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
        all_entries_for_url_check.append({"filename": filename, "record": record})
        manifest_rows.append({
            "filename": filename,
            "rule_id": (record.get("rule", {}) or {}).get("id"),
            "level": (record.get("rule", {}) or {}).get("level"),
            "description": (record.get("rule", {}) or {}).get("description"),
            "source": source,
            "original_filename": original_filename,
            "sha256_full_log": hashlib.sha256((record.get("full_log", "") or "").encode()).hexdigest()[:16],
            "needs_manual_verification": needs_manual_verification,
            "suggested_label_hint": suggested_label_hint,
            "notes": "; ".join(notes),
        })
        return out_path

    report_lines = []
    report_lines.append("# Bao cao trich mau (D2) — doi chieu voi checklist")
    report_lines.append("")
    report_lines.append(f"- Seed: {args.seed}")
    report_lines.append(f"- Raw pool: `{args.raw_pool}` ({len(records)} alert, {len(by_rule)} rule.id)")
    report_lines.append(f"- Curated dir (mauN cu): `{args.curated_dir}`")
    report_lines.append("")

    # ---- 1. Rule bat buoc theo checklist D2 ----
    report_lines.append("## 1. Cac rule checklist yeu cau bo sung")
    report_lines.append("")
    report_lines.append("| rule.id | co trong pool that? | so luong that | da lay | ghi chu |")
    report_lines.append("|---|---|---:|---:|---|")
    for rid, cfg in REQUIRED_RULES.items():
        pool = by_rule.get(rid, [])
        n_take = min(cfg["max_n"], len(pool))
        chosen = sample_for_rule(pool, rid, n_take, rng)
        for i, rec in enumerate(chosen, start=1):
            fname = f"{rid}_{i}.json"
            notes = [cfg["note"]]
            needs_verify = "XAC MINH THU CONG" in cfg["note"] or "KIEM TRA THU CONG" in cfg["note"]
            write_sample(rec, fname, source="raw_pool_sampled", notes=notes,
                         needs_manual_verification=needs_verify)
        status = "CO" if pool else "KHONG CO ALERT THAT"
        report_lines.append(f"| {rid} | {status} | {len(pool)} | {n_take} | {cfg['note']} |")
    report_lines.append("")

    # ---- 2. Mau bo sung cho cac rule khac (de co doi chieu / da dang) ----
    report_lines.append("## 2. Mau bo sung cho cac rule khac trong pool (khong bat buoc, de da dang)")
    report_lines.append("")
    other_rules = [r for r in by_rule if r not in REQUIRED_RULES]
    added_other = 0
    for rid in sorted(other_rules, key=lambda r: -len(by_rule[r])):
        pool = by_rule[rid]
        n_take = min(args.default_per_rule, len(pool))
        chosen = sample_for_rule(pool, rid, n_take, rng)
        for i, rec in enumerate(chosen, start=1):
            fname = f"{rid}_{i}.json"
            write_sample(rec, fname, source="raw_pool_sampled", notes=["mau bo sung, khong nam trong checklist bat buoc"])
        added_other += len(chosen)
    report_lines.append(f"- Da lay them {added_other} mau tu {len(other_rules)} rule con lai "
                         f"(toi da {args.default_per_rule} mau/rule).")
    report_lines.append("")

    # ---- 3. Xu ly cac file curated (mauN cu) - doi ten dung theo rule that ----
    report_lines.append("## 3. Doi chieu va sua cac file mau cu (mauN...)")
    report_lines.append("")
    curated_files = sorted(args.curated_dir.glob("*.json")) if args.curated_dir.exists() else []
    rule_running_index = defaultdict(int)
    # rule_running_index can tinh tiep tu cac file da ghi o buoc 1/2 de khong de
    for row in manifest_rows:
        if row["rule_id"]:
            rule_running_index[row["rule_id"]] = max(
                rule_running_index[row["rule_id"]],
                sum(1 for r in manifest_rows if r["rule_id"] == row["rule_id"] and r["filename"] != "(bo qua - trung lap)")
            )

    report_lines.append(
        "**Luu y quan trong ve nguon goc**: nhieu file trong `mauN...` truoc day duoc mo ta la "
        "\"mot so log duoc viet boi AI dua tren log that\", nhung kiem tra sha256 cho thay phan lon "
        "thuc ra la BAN COPY NGUYEN VAN 100% tu pool that (khong phai AI tong hop). Xem cot cuoi."
    )
    report_lines.append("")
    report_lines.append("| file cu | rule theo TEN file | rule THAT trong noi dung | khop ten/rule? | quyet dinh & nguon that su |")
    report_lines.append("|---|---|---|---|---|")

    for fp in curated_files:
        try:
            rec = json.loads(fp.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            report_lines.append(f"| {fp.name} | - | - | LOI JSON | bo qua |")
            continue
        actual_rid = (rec.get("rule", {}) or {}).get("id", "UNKNOWN")
        actual_desc = (rec.get("rule", {}) or {}).get("description", "")
        actual_level = (rec.get("rule", {}) or {}).get("level", "")

        # doan so rule tu ten file cu (chuoi so cuoi cung truoc .json)
        import re
        m = re.findall(r"(\d+)", fp.stem)
        claimed_rid = m[-1] if m else "?"
        match = "KHOP" if claimed_rid == actual_rid else "LECH"

        rule_running_index[actual_rid] += 1
        new_fname = f"{actual_rid}_{rule_running_index[actual_rid]}.json"

        notes = [f"nguon: file cu '{fp.name}' (rule ten file={claimed_rid}, rule that={actual_rid})"]
        needs_verify = False
        suggested_label_hint = ""
        decision = f"doi ten -> {new_fname}"

        # Kiem tra xem noi dung nay co phai COPY NGUYEN VAN mot alert that trong
        # pool khong (bat ke script co "boc trung" no o buoc 1/2 hay khong).
        rec_hash = sha256_of(rec)
        original_pool_id = raw_hash_to_id.get(rec_hash)
        if original_pool_id:
            source_kind = "raw_pool_verbatim_copy"
            notes.append(f"XAC NHAN: day la BAN COPY NGUYEN VAN (sha256 khop 100%) cua alert that "
                         f"co id='{original_pool_id}' trong pool goc - KHONG phai du lieu AI tu sinh, "
                         "du ten file/mo ta truoc do co the goi y khac")
        else:
            source_kind = "curated_ai_or_manual"
            notes.append("KHONG khop sha256 voi bat ky alert nao trong pool that -> day la mau AI/thu cong "
                         "tu viet moi (thuong vi rule nay khong co alert that trong pool, xem phan 4)")

        if match == "LECH":
            notes.append(f"CANH BAO: ten file cu ngu y rule {claimed_rid} nhung noi dung thuc te la rule {actual_rid} "
                          f"('{actual_desc}') - dung noi dung lam su that, KHONG dung ten file cu")

        # Cac case dac biet da biet truoc theo checklist:
        if actual_rid == "5403" and int(actual_level or 0) <= 4:
            suggested_label_hint = "LANH TINH / NO_ACTION (goi y) - first-time sudo, level thap, khong phai leo thang dac quyen"
            notes.append("khop voi checklist: 'mot mau sudo lan dau, level thap -> nhan lanh tinh/NO_ACTION'")
            decision += " ; GAN NHAN GOI Y = lanh tinh (nguoi gan nhan van phai tu quyet dinh cuoi cung)"

        if actual_rid in KNOWN_POSSIBLY_MISSING_IN_RAW:
            notes.append(f"day la mau CURATED (khong phai alert that) cho SOP '{KNOWN_POSSIBLY_MISSING_IN_RAW[actual_rid]}' "
                         f"- pool that KHONG co alert nao cho rule nay (xem phan 4 ben duoi)")

        write_sample(rec, new_fname, source=source_kind, notes=notes,
                     needs_manual_verification=needs_verify, suggested_label_hint=suggested_label_hint,
                     original_filename=fp.name)

        src_tag = "COPY THAT" if source_kind == "raw_pool_verbatim_copy" else "AI/thu cong MOI"
        report_lines.append(f"| {fp.name} | {claimed_rid} | {actual_rid} ({actual_desc[:40]}) | {match} | {decision} ({src_tag}) |")

    report_lines.append("")

    # ---- 4. SOP khong co alert that trong pool ----
    report_lines.append("## 4. SOP/rule ma pool that KHONG CO alert nao (quyet dinh (a)/(b) can nguoi lam)")
    report_lines.append("")
    for rid, label in KNOWN_POSSIBLY_MISSING_IN_RAW.items():
        real_count = len(by_rule.get(rid, []))
        curated_available = any(r["rule_id"] == rid and r["source"] == "curated_ai_or_manual" for r in manifest_rows)
        report_lines.append(
            f"- **{label}** (rule `{rid}`): {real_count} alert that trong pool. "
            f"{'Co mau curated/AI thay the.' if curated_available else 'KHONG co mau nao ca.'} "
            "Theo checklist D2, can chon: (a) tao du lieu lab moi (vd chay nmap that, kem log firewall co decoder), "
            "hoac (b) ghi ro la gioi han va loai SOP nay khoi danh gia theo lop. "
            "Script nay khong tu quyet dinh thay - **can nguoi phu trach chon va ghi vao day**."
        )
    # rieng 5402 (successful sudo to root) co du lieu that, khac 5403 (first-time, khong phai escalation that su)
    n5402 = len(by_rule.get("5402", []))
    report_lines.append(
        f"- Ghi chu rieng: rule `5402` (\"Successful sudo to ROOT executed\") co {n5402} alert THAT trong pool "
        "va co the la ung vien gan hon cho SOP 'leo thang dac quyen' so voi rule 5403 (chi la lan dau dung sudo, "
        "khong dong nghia voi tan cong). Neu chon dung 5402 lam dai dien cho SOP nay, can lay mau tu day thay vi "
        "chi dung file curated 'priv_esc' cu."
    )
    report_lines.append("")

    # ---- 5. Kiem tra "hai mau giong het nhau do thieu url" ----
    report_lines.append("## 5. Kiem tra hai mau 'giong het nhau' do thieu truong url")
    report_lines.append("")
    lookalikes = detect_missing_url_lookalikes(all_entries_for_url_check)
    if lookalikes:
        for a, b in lookalikes:
            report_lines.append(f"- `{a}` va `{b}`: cung mot `data` (tru url), mot ben co url mot ben khong -> "
                                 "KIEM TRA THU CONG xem co phai loi thieu du lieu dau vao khong.")
    else:
        report_lines.append("- Khong phat hien cap nao trong tap mau da trich lan nay.")
    report_lines.append("")

    # ---- 6. Tom tat trung lap sha256 ----
    n_skipped = sum(1 for r in manifest_rows if r["filename"] == "(bo qua - trung lap)")
    report_lines.append("## 6. Trung lap sha256 (toan bo record)")
    report_lines.append("")
    report_lines.append(f"- So mau bi loai vi trung lap hoan toan voi mau da ghi truoc do: **{n_skipped}**")
    report_lines.append("- Test yeu cau cua checklist ('khong co hai file trung sha256') coi nhu PASS neu so nay = 0 "
                         "sau khi loai bo cac dong '(bo qua - trung lap)' khoi thu muc data/samples.")
    report_lines.append("")

    # ---- Ghi manifest.csv ----
    manifest_path = args.out_dir / "manifest.csv"
    fieldnames = ["filename", "rule_id", "level", "description", "source", "original_filename",
                  "sha256_full_log", "needs_manual_verification", "suggested_label_hint", "notes"]
    with manifest_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in manifest_rows:
            writer.writerow(row)

    report_path = args.out_dir / "extraction_report.md"
    report_path.write_text("\n".join(report_lines), encoding="utf-8")

    n_written = sum(1 for r in manifest_rows if r["filename"] != "(bo qua - trung lap)")
    print(f"Da ghi {n_written} file mau vao {args.out_dir}")
    print(f"Manifest: {manifest_path}")
    print(f"Bao cao: {report_path}")
    if n_skipped:
        print(f"[CANH BAO] {n_skipped} mau bi bo qua vi trung lap sha256 hoan toan.")


if __name__ == "__main__":
    main()
