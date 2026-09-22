#!/usr/bin/env python3
"""
D1 [P0] Ho so du lieu va kich ban tan cong.

Profile phan bo rule/level/agent/srcip cua tap alert goc (NDJSON, moi dong
mot alert Wazuh) va phat hien cac dau hieu can canh bao khi bao cao:
  - Mot rule chiem ty le ap dao (nghi ngo la traffic quet tu dong, khong
    phai chuoi tan cong thuc su).
  - User-agent/ payload trung voi chu ky cong cu quet cong khai (Nikto,
    sqlmap, Shellshock PoC...).
  - Alert trung lap hoan toan (sha256 toan bo record) hoac trung "id".
  - Alert thieu du lieu quan trong (data.srcip, data field noi chung).
  - Khoang thoi gian du lieu bao phu (de biet day co phai mot phien lab
    ngan hay du lieu trai dai nhieu ngay).

Khong tu dong ket luan "day la tan cong that" cho bat ky rule nao - script
chi dua ra so lieu + canh bao, con ket luan cuoi cung phai do nguoi doc
(kem doi chieu thu cong) ghi vao docs/data_provenance.md.

Usage:
    python3 eval/profile_alerts.py \
        --input data/raw/alerts_temp.json \
        --out-md docs/data_provenance.md \
        --out-json docs/data_provenance_stats.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

# Chu ky user-agent / payload hay gap trong cong cu quet tu dong.
# Khong phai bang chinh xac tuyet doi - chi la tin hieu de con nguoi kiem tra lai.
SCANNER_SIGNATURES = {
    "nikto_default_ua": re.compile(r"Mozilla/4\.0 \(compatible; MSIE 6\.0; Windows NT 5\.1\)"),
    "nikto_literal": re.compile(r"nikto", re.IGNORECASE),
    "sqlmap": re.compile(r"sqlmap", re.IGNORECASE),
    "shellshock_poc": re.compile(r"\(\)\s*\{\s*:;\s*\};"),
    "curl_wget_default_ua": re.compile(r"^(curl|Wget)/", re.IGNORECASE),
    "nmap_scanner": re.compile(r"nmap|masscan", re.IGNORECASE),
}


def extract_user_agent(full_log: str) -> str | None:
    """Best-effort: lay truong trong dau nhay kep cuoi cung cua dong access log
    kieu combined log format ("...") "REFERER" "USER-AGENT"."""
    parts = full_log.split('"')
    if len(parts) >= 6:
        return parts[-2]
    return None


def load_ndjson(path: Path):
    n_ok, n_err = 0, 0
    err_examples = []
    records = []
    with path.open("r", encoding="utf-8") as f:
        for i, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
                n_ok += 1
            except json.JSONDecodeError as e:
                n_err += 1
                if len(err_examples) < 5:
                    err_examples.append((i, str(e)))
    return records, n_ok, n_err, err_examples


def whole_record_hash(d: dict) -> str:
    return hashlib.sha256(json.dumps(d, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()


def profile(records: list[dict]) -> dict:
    rule_id_counter = Counter()
    rule_desc = {}
    rule_levels = defaultdict(Counter)  # rule_id -> Counter(level -> count), phong khi 1 rule co >1 level
    level_counter = Counter()
    agent_counter = Counter()
    srcip_counter = Counter()
    group_counter = Counter()
    ua_counter = Counter()
    scanner_hits = defaultdict(Counter)  # signature -> rule_id -> count
    whole_hash_counter = Counter()
    id_field_counter = Counter()
    timestamps = []

    missing_data = 0
    missing_srcip_given_data = 0

    for d in records:
        rule = d.get("rule", {}) or {}
        rid = rule.get("id", "UNKNOWN")
        rule_id_counter[rid] += 1
        rule_desc[rid] = rule.get("description", "")
        lvl = rule.get("level", "UNKNOWN")
        rule_levels[rid][lvl] += 1
        level_counter[lvl] += 1

        agent = d.get("agent", {}) or {}
        agent_counter[agent.get("name", "UNKNOWN")] += 1

        data = d.get("data")
        if not data:
            missing_data += 1
        else:
            ip = data.get("srcip")
            if ip:
                srcip_counter[ip] += 1
            else:
                missing_srcip_given_data += 1

        for g in rule.get("groups", []) or []:
            group_counter[g] += 1

        full_log = d.get("full_log", "") or ""
        ua = extract_user_agent(full_log)
        if ua:
            ua_counter[ua] += 1

        haystack = full_log + " " + (ua or "")
        for sig_name, pattern in SCANNER_SIGNATURES.items():
            if pattern.search(haystack):
                scanner_hits[sig_name][rid] += 1

        whole_hash_counter[whole_record_hash(d)] += 1
        id_field_counter[d.get("id", "UNKNOWN")] += 1

        ts = d.get("timestamp")
        if ts:
            timestamps.append(ts)

    total = len(records)
    top_rule_id, top_rule_count = (rule_id_counter.most_common(1) or [(None, 0)])[0]
    top_rule_share = (top_rule_count / total) if total else 0.0

    dup_whole = {h: c for h, c in whole_hash_counter.items() if c > 1}
    dup_id = {i: c for i, c in id_field_counter.items() if c > 1}

    return {
        "total_alerts": total,
        "unique_rule_ids": len(rule_id_counter),
        "rule_id_counts": rule_id_counter.most_common(),
        "rule_descriptions": rule_desc,
        "rule_levels": {
            rid: {
                "levels": dict(counter.most_common()),
                "mixed": len(counter) > 1,
                "main_level": counter.most_common(1)[0][0],
            }
            for rid, counter in rule_levels.items()
        },
        "level_counts": sorted(level_counter.items(), key=lambda x: (str(x[0]))),
        "agent_counts": agent_counter.most_common(),
        "srcip_counts": srcip_counter.most_common(),
        "group_counts": group_counter.most_common(),
        "top_rule_id": top_rule_id,
        "top_rule_count": top_rule_count,
        "top_rule_share": top_rule_share,
        "missing_data_field": missing_data,
        "missing_srcip_given_data": missing_srcip_given_data,
        "scanner_signature_hits": {
            sig: dict(counter.most_common()) for sig, counter in scanner_hits.items() if counter
        },
        "top_user_agents": ua_counter.most_common(15),
        "exact_duplicate_whole_record_groups": len(dup_whole),
        "exact_duplicate_whole_record_total_extra": sum(c - 1 for c in dup_whole.values()),
        "duplicate_id_field_groups": len(dup_id),
        "timestamp_min": min(timestamps) if timestamps else None,
        "timestamp_max": max(timestamps) if timestamps else None,
    }


def render_markdown(stats: dict, input_path: Path) -> str:
    lines = []
    lines.append("# Data provenance & profiling — tap alert goc")
    lines.append("")
    lines.append(f"- Nguon file: `{input_path}`")
    lines.append(f"- Sinh boi: `eval/profile_alerts.py` luc {datetime.now().isoformat(timespec='seconds')}")
    lines.append(f"- Tong so alert: **{stats['total_alerts']}**")
    lines.append(f"- Khoang thoi gian: `{stats['timestamp_min']}` -> `{stats['timestamp_max']}`")
    lines.append(f"- So rule.id khac nhau: **{stats['unique_rule_ids']}**")
    lines.append("")
    lines.append("## ⚠️ Nguon goc du lieu — CAN GHI RO TRUOC KHI DUNG DE DANH GIA")
    lines.append("")
    lines.append(
        "- [ ] Ai chay cong cu gi, luc nao de sinh ra file nay? "
        "(dien tay sau khi hoi nguoi da chay lab — script khong biet duoc.)"
    )
    lines.append(
        f"- Toan bo alert chi den tu **{len(stats['agent_counts'])} agent** "
        f"va **{len(stats['srcip_counts'])} srcip khac nhau** (xem bang ben duoi). "
        "Neu chi co 1 srcip tan cong -> day rat co the la 1 phien lab don, khong phai du lieu san xuat that."
    )
    top_share_pct = stats["top_rule_share"] * 100
    lines.append("")
    lines.append(
        f"- **Canh bao mat can bang nhan**: rule `{stats['top_rule_id']}` "
        f"(\"{stats['rule_descriptions'].get(stats['top_rule_id'], '')}\") "
        f"chiem **{stats['top_rule_count']}/{stats['total_alerts']} ({top_share_pct:.1f}%)** tong so alert. "
        "Neu lay mau ngau nhien thuan tuy, ~85% mau se roi vao dung 1 rule nay "
        "(dung dieu D3 da canh bao) -> **bat buoc lay mau phan tang theo rule.id**, khong lay ngau nhien."
    )
    if stats["scanner_signature_hits"]:
        lines.append("")
        lines.append(
            "- **Dau hieu quet tu dong (scanner)**: phat hien cac chu ky sau trong full_log/user-agent. "
            "Day la TIN HIEU, khong phai ket luan cuoi — can doi chieu thu cong truoc khi ghi vao bao cao "
            "la \"day khong phai tan cong thuc\":"
        )
        for sig, per_rule in stats["scanner_signature_hits"].items():
            total_sig = sum(per_rule.values())
            rules_str = ", ".join(f"rule {r} (x{c})" for r, c in list(per_rule.items())[:6])
            lines.append(f"    - `{sig}`: {total_sig} alert — xuat hien o {rules_str}")
        if "nikto_default_ua" in stats["scanner_signature_hits"]:
            n = sum(stats["scanner_signature_hits"]["nikto_default_ua"].values())
            lines.append(
                f"    - Rieng chu ky User-Agent mac dinh cua Nikto xuat hien **{n} lan** "
                f"trong tong so **{stats['top_rule_count']}** alert cua rule `{stats['top_rule_id']}` "
                "-> phan lon (co the gan nhu toan bo) so alert 'web attack' nay nhieu kha nang la "
                "**traffic quet tu dong cua Nikto**, khong phai tan cong thu cong thuc su. "
                "**Phai ghi ro dieu nay trong bao cao, khong duoc goi day la 'tan cong SQLi/XSS/Shellshock thuc te'** "
                "neu khong doi chieu duoc bang chung khac."
            )
    else:
        lines.append("- Khong phat hien chu ky scanner da biet trong danh sach kiem tra (co the can bo sung them mau).")

    if stats["exact_duplicate_whole_record_groups"] or stats["duplicate_id_field_groups"]:
        lines.append("")
        lines.append(
            f"- **Trung lap**: {stats['exact_duplicate_whole_record_groups']} nhom ban ghi trung sha256 hoan toan "
            f"({stats['exact_duplicate_whole_record_total_extra']} ban ghi thua), "
            f"{stats['duplicate_id_field_groups']} nhom trung truong `id`."
        )
    else:
        lines.append(
            "- Khong phat hien alert trung lap hoan toan (sha256 toan bo record) va khong trung truong `id` "
            "trong tap alert goc nay."
        )

    if stats["missing_data_field"] or stats["missing_srcip_given_data"]:
        lines.append("")
        lines.append(
            f"- Thieu du lieu: {stats['missing_data_field']} alert khong co truong `data`; "
            f"{stats['missing_srcip_given_data']} alert co `data` nhung thieu `srcip`."
        )

    lines.append("")
    lines.append("## Phan bo theo rule.id")
    lines.append("")
    lines.append("| rule.id | so luong | % | level | mo ta |")
    lines.append("|---|---:|---:|---|---|")
    # level per rule: lay level pho bien nhat cho moi rule de hien thi (tham khao)
    for rid, count in stats["rule_id_counts"]:
        pct = count / stats["total_alerts"] * 100 if stats["total_alerts"] else 0
        desc = stats["rule_descriptions"].get(rid, "")
        lvl_info = stats["rule_levels"].get(rid, {})
        lvl_display = str(lvl_info.get("main_level", ""))
        if lvl_info.get("mixed"):
            lvl_display += " (mixed: " + ", ".join(f"{k}×{v}" for k, v in lvl_info["levels"].items()) + ")"
        lines.append(f"| {rid} | {count} | {pct:.2f}% | {lvl_display} | {desc} |")

    lines.append("")
    lines.append("## Phan bo theo level")
    lines.append("")
    lines.append("| level | so luong |")
    lines.append("|---|---:|")
    for lvl, count in stats["level_counts"]:
        lines.append(f"| {lvl} | {count} |")

    lines.append("")
    lines.append("## Phan bo theo agent")
    lines.append("")
    lines.append("| agent | so luong |")
    lines.append("|---|---:|")
    for a, c in stats["agent_counts"]:
        lines.append(f"| {a} | {c} |")

    lines.append("")
    lines.append("## Phan bo theo srcip (top 20)")
    lines.append("")
    lines.append("| srcip | so luong |")
    lines.append("|---|---:|")
    for ip, c in stats["srcip_counts"][:20]:
        lines.append(f"| {ip} | {c} |")

    lines.append("")
    lines.append("## Top groups (rule.groups)")
    lines.append("")
    lines.append("| group | so luong |")
    lines.append("|---|---:|")
    for g, c in stats["group_counts"][:20]:
        lines.append(f"| {g} | {c} |")

    lines.append("")
    lines.append("## Ghi chu ky quy tinh lai so nhom dang dung (muc 0)")
    lines.append("")
    lines.append(
        "So lieu ben tren la ket qua tinh lai truc tiep tu file goc bang script nay "
        "(khong copy tay), dung de doi chieu voi cac con so 'nhom' da dung truoc do trong de cuong/bao cao. "
        "Neu lech nhau, uu tien so lieu trong file nay (co the tai lap) va cap nhat lai bao cao cu."
    )
    lines.append("")
    lines.append("---")
    lines.append(
        "_File nay duoc sinh tu dong boi `eval/profile_alerts.py`. "
        "Phan '⚠️ Nguon goc du lieu' can nguoi phu trach dien tay muc dau tien (ai chay cong cu gi, luc nao) "
        "va xac nhan lai cac canh bao truoc khi dua vao bao cao chinh thuc._"
    )
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input", type=Path, default=Path("data/raw/alerts_temp.json"),
                     help="Duong dan file NDJSON alert goc")
    ap.add_argument("--out-md", type=Path, default=Path("docs/data_provenance.md"),
                     help="Duong dan file markdown ket qua")
    ap.add_argument("--out-json", type=Path, default=Path("docs/data_provenance_stats.json"),
                     help="Duong dan file JSON so lieu tho (de script khac tai su dung)")
    args = ap.parse_args()

    if not args.input.exists():
        print(f"[LOI] Khong tim thay file input: {args.input}", file=sys.stderr)
        sys.exit(1)

    records, n_ok, n_err, err_examples = load_ndjson(args.input)
    if n_err:
        print(f"[CANH BAO] {n_err} dong loi JSON, vi du: {err_examples}", file=sys.stderr)
    print(f"Da doc {n_ok} alert hop le tu {args.input}")

    stats = profile(records)

    args.out_md.parent.mkdir(parents=True, exist_ok=True)
    args.out_json.parent.mkdir(parents=True, exist_ok=True)

    md = render_markdown(stats, args.input)
    args.out_md.write_text(md, encoding="utf-8")
    args.out_json.write_text(json.dumps(stats, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"Da ghi: {args.out_md}")
    print(f"Da ghi: {args.out_json}")
    print()
    print(f"Tong alert: {stats['total_alerts']} | Unique rule.id: {stats['unique_rule_ids']} | "
          f"Rule chiem da so: {stats['top_rule_id']} ({stats['top_rule_share']*100:.1f}%)")


if __name__ == "__main__":
    main()
