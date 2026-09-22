#!/usr/bin/env python3
"""
D8 [P2] Hang doi/gom nhom - soc_copilot/triage.py

Doc NDJSON alert (kieu Wazuh), gom nhom theo (rule.id, srcip), dem so luong,
lay level cao nhat trong nhom, sap theo muc uu tien, tra ve 1 alert dai dien
cho moi nhom - DAY LA PHAN DUY NHAT trong toan bo he thong thuc su cham toi
"alert fatigue" ma de cuong lay lam dong luc (cac phan D1-D7 chi lam eval, KHONG
lam giam khoi luong alert nguoi phai xem).

Neu phan nay khong duoc dung/khong duoc tich hop vao UI that, PHAI ha nhe dong
luc trong de cuong: du an chi con la "cong cu ho tro tra SOP cho tung alert",
KHONG con la "giam khoi luong alert fatigue" nhu tuyen bo ban dau.

Uu tien duoc tinh nhu the nao (co the dieu chinh qua tham so):
    priority_score = max_level * 10 + min(count, 50)
    - max_level la yeu to chinh (alert nghiem trong hon luon uu tien truoc).
    - count (so lan xuat hien, gioi han o 50 de tranh 1 nhom qua nhieu lan lan at
      het cac nhom nghiem trong khac) la yeu to phu - nhom lap lai nhieu lan
      trong thoi gian ngan cung dang chu y hon (vd brute force dang dien ra).
    Day la CONG THUC GOI Y, khong phai chuan tuyet doi - Tai/Binh nen dieu chinh
    trong so 10 nay dua theo phan hoi thuc te tu SOC analyst khi dung tab
    "Hang doi" trong UI.

Dung nhu module (import) de UI (Tai lam) goi truc tiep, hoac chay CLI de xem
nhanh ket qua dang bang trong terminal.

Usage (CLI):
    python3 soc_copilot/triage.py --input data/raw/alerts_temp.json --top 20

Usage (import trong UI):
    from soc_copilot.triage import load_alerts_ndjson, group_alerts
    alerts = load_alerts_ndjson("data/raw/alerts_temp.json")
    queue = group_alerts(alerts)   # list[AlertGroup], da sap theo uu tien
    for g in queue[:20]:
        ...  # hien thi g.rule_id, g.srcip, g.count, g.max_level, g.representative_alert
"""
from __future__ import annotations

import argparse
import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class AlertGroup:
    rule_id: str
    srcip: str
    count: int
    max_level: int
    rule_description: str
    first_seen: str
    last_seen: str
    priority_score: float
    representative_alert: dict = field(repr=False)
    all_alert_ids: list = field(default_factory=list, repr=False)

    def to_dict(self, include_representative: bool = True) -> dict:
        d = {
            "rule_id": self.rule_id,
            "srcip": self.srcip,
            "count": self.count,
            "max_level": self.max_level,
            "rule_description": self.rule_description,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "priority_score": self.priority_score,
        }
        if include_representative:
            d["representative_alert"] = self.representative_alert
        return d


def load_alerts_ndjson(path: str | Path) -> list[dict]:
    path = Path(path)
    alerts = []
    n_err = 0
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                alerts.append(json.loads(line))
            except json.JSONDecodeError:
                n_err += 1
    if n_err:
        print(f"[CANH BAO] {n_err} dong loi JSON bi bo qua khi doc {path}")
    return alerts


def _unwrap_source(alert: dict) -> dict:
    """Ho tro alert bi boc trong '_source' (xem data/adversarial/ ca 10, 11) - neu
    alert khong co 'rule' o cap ngoai cung nhung co '_source' chua 'rule', dung
    noi dung ben trong. Giup soc_copilot/triage.py khong crash tren du lieu 'bay'."""
    if "rule" not in alert and isinstance(alert.get("_source"), dict):
        return alert["_source"]
    return alert


def group_alerts(alerts: list[dict], level_weight: float = 10.0, count_cap: int = 50) -> list[AlertGroup]:
    """Gom nhom theo (rule.id, srcip). Alert thieu srcip duoc gom vao srcip
    '(khong xac dinh)' rieng - KHONG bi loai bo, vi thieu srcip khong co nghia
    la khong quan trong (xem data/adversarial/04_missing_srcip_and_mitre.json)."""
    groups: dict[tuple, dict] = {}

    for raw_alert in alerts:
        alert = _unwrap_source(raw_alert)
        rule = alert.get("rule", {}) or {}
        rule_id = str(rule.get("id", "UNKNOWN"))
        level = rule.get("level")
        try:
            level = int(level)
        except (TypeError, ValueError):
            level = 0
        desc = rule.get("description", "")
        data = alert.get("data") or {}
        srcip = data.get("srcip") or "(khong xac dinh)"
        ts = alert.get("timestamp", "")
        alert_id = alert.get("id", "")

        key = (rule_id, srcip)
        if key not in groups:
            groups[key] = {
                "rule_id": rule_id, "srcip": srcip, "count": 0, "max_level": level,
                "rule_description": desc, "first_seen": ts, "last_seen": ts,
                "representative_alert": alert, "all_alert_ids": [],
            }
        g = groups[key]
        g["count"] += 1
        g["all_alert_ids"].append(alert_id)
        if ts and (not g["first_seen"] or ts < g["first_seen"]):
            g["first_seen"] = ts
        if ts and (not g["last_seen"] or ts > g["last_seen"]):
            g["last_seen"] = ts
        if level > g["max_level"]:
            g["max_level"] = level
            g["representative_alert"] = alert  # dai dien = alert co level cao nhat trong nhom
            g["rule_description"] = desc

    result = []
    for g in groups.values():
        priority = g["max_level"] * level_weight + min(g["count"], count_cap)
        result.append(AlertGroup(
            rule_id=g["rule_id"], srcip=g["srcip"], count=g["count"], max_level=g["max_level"],
            rule_description=g["rule_description"], first_seen=g["first_seen"], last_seen=g["last_seen"],
            priority_score=priority, representative_alert=g["representative_alert"],
            all_alert_ids=g["all_alert_ids"],
        ))

    result.sort(key=lambda g: g.priority_score, reverse=True)
    return result


def print_table(groups: list[AlertGroup], top: int) -> None:
    print(f"{'STT':<4} {'diem':<7} {'level':<6} {'so lan':<7} {'rule.id':<10} {'srcip':<16} {'mo ta'}")
    print("-" * 100)
    for i, g in enumerate(groups[:top], start=1):
        print(f"{i:<4} {g.priority_score:<7.1f} {g.max_level:<6} {g.count:<7} {g.rule_id:<10} "
              f"{g.srcip:<16} {g.rule_description[:50]}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input", type=Path, required=True, help="File NDJSON alert (vd data/raw/alerts_temp.json)")
    ap.add_argument("--top", type=int, default=20, help="Chi hien thi N nhom uu tien cao nhat")
    ap.add_argument("--level-weight", type=float, default=10.0)
    ap.add_argument("--count-cap", type=int, default=50)
    ap.add_argument("--out-json", type=Path, default=None,
                     help="Neu chi dinh, ghi TOAN BO hang doi (khong gioi han --top) ra file JSON "
                          "cho UI (Tai) doc truc tiep, khong can chay lai script nay tu Python")
    args = ap.parse_args()

    alerts = load_alerts_ndjson(args.input)
    print(f"Da doc {len(alerts)} alert tu {args.input}")

    groups = group_alerts(alerts, level_weight=args.level_weight, count_cap=args.count_cap)
    print(f"Gom duoc {len(groups)} nhom (giam {len(alerts)} -> {len(groups)}, "
          f"ty le rut gon {100 * (1 - len(groups) / max(1, len(alerts))):.1f}%)")
    print()

    print_table(groups, args.top)

    if args.out_json:
        args.out_json.parent.mkdir(parents=True, exist_ok=True)
        payload = [g.to_dict(include_representative=True) for g in groups]
        args.out_json.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"\nDa ghi toan bo hang doi ({len(groups)} nhom) vao: {args.out_json}")


if __name__ == "__main__":
    main()
