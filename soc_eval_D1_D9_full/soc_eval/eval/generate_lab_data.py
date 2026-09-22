#!/usr/bin/env python3
"""
D2 - Phuong an (a) da chon: tao du lieu lab moi cho 2 SOP khong co alert that
trong pool: port scan va privilege escalation.

QUAN TRONG - doc truoc khi dung:
Moi truong chay script nay KHONG co ket noi mang toi may lab (SIFT VM) cua ban,
nen KHONG THE tu chay nmap that va bat log firewall that. Thay vao do, script
nay TAI TAO alert theo dung format/decoder that da quan sat duoc trong
data/raw/alerts_temp.json (iptables decoder cho port scan, sudo decoder cho
privilege escalation), voi timing/port/command hop ly va co seed.

Day la du lieu "lab_synthetic", KHONG PHAI capture that. Trong docs/environment.md
(D7) va docs/data_provenance.md (D1) PHAI ghi ro nguon goc nay.

Neu sau nay ban tu chay nmap that tren SIFT VM va lay duoc log that, hay thay
truc tiep cac file trong data/lab/ bang log that (giu nguyen ten file/rule.id
de eval/run_eval.py khong can sua) roi chay lai eval/extract_samples.py.

--- Port scan ---
Tai su dung dung schema cua rule custom "100200" da thay trong
mau10_portscan_100200.json (iptables DROP, nhieu cong, cung srcip trong thoi
gian ngan). Sinh THEM 1 phien scan moi (khac srcip/port/thoi diem voi mau cu)
de co >1 mau doc lap cho rule nay, cong them cac alert iptables DROP rieng le
(chua bi gom nhom) lam "previous_output" hop ly.

--- Privilege escalation ---
Du lieu that trong pool chi co rule 5402/5403 (sudo lan dau / sudo thanh cong)
voi lenh VO HAI (vd "tail -f auth.log") - KHONG phai kich ban leo thang dac
quyen thuc su. Vi chua co rule custom nao cho "privilege escalation attack"
trong bo rule hien tai (khac voi portscan/webshell/bruteforce da co san rule
custom 100200/100210/100220), script nay DE XUAT rule id moi **100230**
("Suspicious privilege escalation via sudo - sensitive file/command access")
tiep noi dung danh so custom rule dang dung. **Rule id nay la DE XUAT, chua
duoc xac nhan trong SOC copilot that - can Tai/Binh xac nhan hoac doi so khac
neu bi trung voi rule da co.**

Kich ban: mot user (co the la user vua bi ssh brute-force thanh cong tu cung
srcip 192.168.26.10 trong pool that) dung sudo de doc /etc/shadow va sua
/etc/sudoers - hanh vi dien hinh cua leo thang dac quyen (MITRE T1548.003),
khac han voi "tail -f auth.log" vo hai da co.

Usage:
    python3 eval/generate_lab_data.py --out-dir data/lab --seed 42
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timedelta
from pathlib import Path

BASE_DAY = "2026-09-21"  # ngay lab moi, khac voi ngay cua pool that (2026-08-28)
                          # de khong bi nham la trich tu pool that
ATTACKER_IP = "192.168.26.20"   # co tinh khac voi 192.168.26.10 (srcip trong pool that)
TARGET_IP = "192.168.26.50"


def ts(offset_seconds: float) -> str:
    base = datetime.fromisoformat(f"{BASE_DAY}T09:00:00.000000+07:00")
    t = base + timedelta(seconds=offset_seconds)
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond:06d}"[:6] + "+0700"


def gen_portscan_session(session_no: int) -> list[dict]:
    """Mot phien port scan: nhieu alert IPTABLES-DROP rieng le tren cac cong
    khac nhau trong vong vai giay, gom lai thanh 1 alert tong hop rule 100200,
    dung dung schema/groups/mitre da thay trong mau10 goc."""
    ports = [21, 22, 23, 25, 80, 135, 139, 143, 443, 445, 993, 1433, 3306, 3389, 5900, 8080]
    t0 = session_no * 300  # cach nhau 5 phut moi phien de khong trung timestamp
    lines = []
    for i, p in enumerate(ports):
        line_ts = ts(t0 + i * 0.15)
        sport = 50000 + session_no * 100 + i
        lines.append(
            f"{line_ts} localhost kernel: IPTABLES-DROP: IN=eth0 OUT= "
            f"SRC={ATTACKER_IP} DST={TARGET_IP} PROTO=TCP SPT={sport} DPT={p} "
        )
    full_log = lines[-1]
    previous_output = "\n".join(lines[:-1])
    alert_id = f"lab.portscan.{session_no}.{int(t0)}"

    alert = {
        "timestamp": ts(t0 + (len(ports) - 1) * 0.15),
        "rule": {
            "level": 10,
            "description": "Possible port scan detected: multiple ports scanned from same source in a short period.",
            "id": "100200",
            "mitre": {
                "id": ["T1046"],
                "tactic": ["Discovery"],
                "technique": ["Network Service Discovery"],
            },
            "frequency": len(ports),
            "firedtimes": 1,
            "mail": False,
            "groups": ["firewall", "recon", "port_scan"],
            "pci_dss": ["11.4"],
            "gdpr": ["IV_35.7.d"],
            "nist_800_53": ["SI.4", "SA.11"],
            "tsc": ["CC6.1", "CC6.6", "CC7.1"],
        },
        "agent": {"id": "000", "name": "siftworkstation"},
        "manager": {"name": "siftworkstation"},
        "id": alert_id,
        "previous_output": previous_output,
        "full_log": full_log,
        "predecoder": {"program_name": "kernel", "timestamp": ts(t0 + (len(ports) - 1) * 0.15)},
        "decoder": {"name": "iptables"},
        "data": {
            "srcip": ATTACKER_IP,
            "dstip": TARGET_IP,
            "protocol": "TCP",
            "dstport": str(ports[-1]),
            "action": "DROP",
            "ports_scanned": ",".join(str(p) for p in ports),
        },
        "location": "/var/log/kern.log",
        "_lab_synthetic": True,
        "_lab_synthetic_note": (
            "Alert nay LA DU LIEU LAB TAI TAO (khong phai capture nmap that), sinh boi "
            "eval/generate_lab_data.py theo Phuong an (a) cua checklist D2. Format duoc mo phong "
            "dung theo mau10_portscan_100200.json va decoder iptables that trong pool. "
            "Neu co log nmap that, hay thay the file nay va giu nguyen ten."
        ),
    }
    return [alert]


def gen_privesc_scenario(scenario_no: int) -> list[dict]:
    """Mot chuoi 2 alert: (1) sudo thanh cong nhung lenh nhay cam (doc /etc/shadow),
    (2) sua /etc/sudoers de them quyen NOPASSWD - dien hinh leo thang dac quyen
    that su, khac voi 'tail -f auth.log' vo hai da co trong pool that."""
    t0 = 10_000 + scenario_no * 300
    user = "sansforensics" if scenario_no % 2 == 0 else "webadmin"
    commands = [
        ("/usr/bin/cat /etc/shadow", "doc file mat khau bam - do tham do he thong"),
        ("/usr/bin/visudo -f /etc/sudoers.d/99-tmp -- -c \"webadmin ALL=(ALL) NOPASSWD:ALL\"",
         "them quyen sudo khong can mat khau - leo thang dac quyen ben vung"),
    ]
    alerts = []
    for i, (cmd, _reason) in enumerate(commands):
        line_ts = ts(t0 + i * 4)
        full_log = (
            f"{line_ts.split('+')[0]}+07:00 siftworkstation sudo[{5000 + scenario_no * 3 + i}]: "
            f"{user} : TTY=pts/1 ; PWD=/home/{user} ; USER=root ; COMMAND={cmd}"
        )
        alert = {
            "timestamp": line_ts,
            "rule": {
                "level": 12,
                "description": "Suspicious privilege escalation via sudo: sensitive file or sudoers access "
                                "(DE XUAT rule 100230 - CHUA XAC NHAN trong bo rule that, can Tai/Binh duyet).",
                "id": "100230",
                "mitre": {
                    "id": ["T1548.003", "T1078"],
                    "tactic": ["Privilege Escalation", "Defense Evasion"],
                    "technique": ["Sudo and Sudo Caching"],
                },
                "firedtimes": 1,
                "mail": True,
                "groups": ["syslog", "sudo", "privilege_escalation"],
                "pci_dss": ["10.2.5", "10.2.2"],
                "gdpr": ["IV_32.2"],
                "nist_800_53": ["AC.6", "AC.7", "AU.14"],
            },
            "agent": {"id": "000", "name": "siftworkstation"},
            "manager": {"name": "siftworkstation"},
            "id": f"lab.privesc.{scenario_no}.{i}.{int(t0)}",
            "full_log": full_log,
            "predecoder": {"program_name": "sudo", "timestamp": line_ts.split("+")[0] + "+07:00"},
            "decoder": {"parent": "sudo", "name": "sudo"},
            "data": {
                "srcuser": user,
                "dstuser": "root",
                "tty": "pts/1",
                "pwd": f"/home/{user}",
                "command": cmd,
            },
            "location": "journald",
            "_lab_synthetic": True,
            "_lab_synthetic_note": (
                "Alert nay LA DU LIEU LAB TAI TAO, sinh boi eval/generate_lab_data.py theo Phuong an (a) "
                "cua checklist D2. Rule id '100230' la DE XUAT, CHUA duoc xac nhan la ID chinh thuc trong "
                "SOC copilot - can Tai/Binh duyet truoc khi dung chinh thuc. Kich ban mo phong theo dung "
                "format decoder 'sudo' that (xem rule 5402 that trong pool), nhung thay lenh vo hai bang "
                "lenh nhay cam de phan anh dung SOP 'leo thang dac quyen'."
            ),
        }
        alerts.append(alert)
    return alerts


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out-dir", type=Path, default=Path("data/lab"))
    ap.add_argument("--n-portscan-sessions", type=int, default=2)
    ap.add_argument("--n-privesc-scenarios", type=int, default=2)
    ap.add_argument("--seed", type=int, default=42)  # giu de nhat quan giao dien voi cac script khac
    args = ap.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)

    written = []
    for s in range(1, args.n_portscan_sessions + 1):
        for alert in gen_portscan_session(s):
            fname = f"100200_lab_{s}.json"
            (args.out_dir / fname).write_text(json.dumps(alert, ensure_ascii=False, indent=2), encoding="utf-8")
            written.append(fname)

    for s in range(1, args.n_privesc_scenarios + 1):
        for i, alert in enumerate(gen_privesc_scenario(s), start=1):
            fname = f"100230_lab_{s}_{i}.json"
            (args.out_dir / fname).write_text(json.dumps(alert, ensure_ascii=False, indent=2), encoding="utf-8")
            written.append(fname)

    readme = args.out_dir / "README_LAB_DATA.md"
    readme.write_text(
        "# Du lieu lab tong hop (Phuong an (a), D2)\n\n"
        "Cac file trong thu muc nay LA DU LIEU LAB TAI TAO bang script "
        "`eval/generate_lab_data.py`, KHONG PHAI capture nmap/attack that, vi moi "
        "truong chay script khong co ket noi toi may lab that.\n\n"
        "- `100200_lab_*.json`: port scan (rule 100200, da co san trong bo rule - dung lai dung schema).\n"
        "- `100230_lab_*.json`: privilege escalation (rule **100230 la DE XUAT MOI**, "
        "CHUA duoc xac nhan la ID chinh thuc - Tai/Binh can duyet hoac doi so khac neu trung).\n\n"
        "Neu sau nay chay duoc nmap that tren SIFT VM / tao duoc escalation that, "
        "hay thay truc tiep noi dung cac file nay bang log that (giu nguyen ten file) "
        "roi ghi lai vao docs/data_provenance.md rang du lieu da duoc thay bang capture that.\n\n"
        f"So file da sinh: {len(written)}\n",
        encoding="utf-8",
    )

    print(f"Da sinh {len(written)} alert lab vao {args.out_dir}")
    for f in written:
        print(" -", f)
    print(f"Doc them: {readme}")


if __name__ == "__main__":
    main()
