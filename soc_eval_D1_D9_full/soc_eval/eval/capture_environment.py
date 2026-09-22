#!/usr/bin/env python3
"""
D7 [P1] Tai lap - eval/capture_environment.py

Tu dong thu thap cang nhieu thong tin cang tot ve moi truong chay eval, ghi vao
docs/environment.md, de nguoi khac (hoac chinh minh 6 thang sau) co the tai lap
lai ket qua. Nhung gi KHONG lay duoc tu dong (vd khong co Ollama trong moi truong
nay) se ghi ro "KHONG LAY DUOC" thay vi bo trong hoac bia so.

Thu thap:
    - He dieu hanh, kien truc CPU, RAM (best-effort, tuy OS)
    - Phien ban Python + toan bo package da cai (pip freeze)
    - Phien ban Ollama (neu co) + 'ollama show <model>' cho tung model duoc liet ke
      qua --models (digest, family, parameter size, quantization)
    - git commit hien tai cua repo (neu la git repo)
    - Seed dang dung trong cac script khac (doc truc tiep tu source de luon dong bo,
      khong phai goi tay 1 con so co the lech voi code that)

Usage (chay tren MAY THAT co Ollama, sau khi da cai dat day du):
    python3 eval/capture_environment.py --models qwen2.5:3b qwen2.5:7b \
        --out docs/environment.md

Chay lai script nay MOI LAN truoc khi bat dau 1 dot chay eval chinh thuc (D5),
vi phien ban Ollama/model co the da doi ke tu lan truoc.
"""
from __future__ import annotations

import argparse
import platform
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path


def run_cmd(cmd: list[str], timeout: float = 15.0) -> tuple[bool, str]:
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if out.returncode == 0:
            return True, out.stdout.strip()
        return False, f"(lenh loi, returncode={out.returncode}) {out.stderr.strip()}"
    except FileNotFoundError:
        return False, f"(khong tim thay lenh '{cmd[0]}' - chua cai dat / khong co trong PATH)"
    except subprocess.TimeoutExpired:
        return False, f"(lenh qua {timeout}s, da huy)"
    except Exception as e:
        return False, f"(loi khong xac dinh: {e})"


def get_os_info() -> dict:
    info = {
        "he_dieu_hanh": platform.platform(),
        "kien_truc_cpu": platform.machine(),
        "processor": platform.processor() or "(khong lay duoc chi tiet processor)",
    }
    ok, ram = run_cmd(["bash", "-c", "free -h 2>/dev/null | grep Mem || echo 'khong lay duoc (khong phai Linux hoac thieu lenh free)'"])
    info["ram"] = ram
    return info


def get_python_info() -> dict:
    return {
        "python_version": sys.version.replace("\n", " "),
        "python_executable": sys.executable,
    }


def get_pip_freeze() -> str:
    ok, out = run_cmd([sys.executable, "-m", "pip", "freeze"])
    return out if ok else f"KHONG LAY DUOC: {out}"


def get_git_info() -> dict:
    ok_commit, commit = run_cmd(["git", "rev-parse", "HEAD"])
    ok_branch, branch = run_cmd(["git", "rev-parse", "--abbrev-ref", "HEAD"])
    ok_status, status = run_cmd(["git", "status", "--porcelain"])
    return {
        "commit": commit if ok_commit else "KHONG LAY DUOC (khong phai git repo?)",
        "branch": branch if ok_branch else "KHONG LAY DUOC",
        "co_thay_doi_chua_commit": ("KHONG" if (ok_status and not status) else
                                     ("CO - xem 'git status', ket qua co the KHONG tai lap duoc chinh xac"
                                      if ok_status else "KHONG XAC DINH DUOC")),
    }


def get_ollama_info(models: list[str]) -> dict:
    ok_ver, version = run_cmd(["ollama", "--version"])
    result = {"ollama_version": version if ok_ver else f"KHONG LAY DUOC: {version}", "models": {}}
    if not ok_ver:
        for m in models:
            result["models"][m] = "KHONG LAY DUOC - Ollama khong san sang tren may nay"
        return result

    ok_list, listing = run_cmd(["ollama", "list"])
    for m in models:
        ok_show, show_out = run_cmd(["ollama", "show", m])
        digest = "KHONG XAC DINH"
        if ok_list:
            for line in listing.splitlines()[1:]:
                parts = line.split()
                if parts and parts[0] == m:
                    digest = parts[1] if len(parts) > 1 else "KHONG XAC DINH"
                    break
        result["models"][m] = {
            "digest_id_ngan": digest,
            "ollama_show_output": show_out if ok_show else f"KHONG LAY DUOC: {show_out}",
        }
    return result


def extract_seeds_from_source(eval_dir: Path) -> dict:
    """Doc truc tiep tu source code cac script D1-D5 de biet seed MAC DINH dang dung,
    tranh ghi tay 1 con so co the lech voi code that neu code doi sau nay."""
    seeds = {}
    patterns = {
        "extract_samples.py": r'"--seed".*?default=(\d+)',
        "build_labeling_set.py": r'"--seed".*?default=(\d+)',
        "generate_lab_data.py": r'"--seed".*?default=(\d+)',
    }
    for fname, pattern in patterns.items():
        fpath = eval_dir / fname
        if fpath.exists():
            text = fpath.read_text(encoding="utf-8")
            m = re.search(pattern, text, re.DOTALL)
            seeds[fname] = m.group(1) if m else "KHONG DOC DUOC (kiem tra lai regex/code)"
        else:
            seeds[fname] = "KHONG THAY FILE"
    return seeds


def render_md(os_info, py_info, pip_freeze, git_info, ollama_info, seeds, models) -> str:
    lines = []
    lines.append("# docs/environment.md — Cau hinh moi truong chay eval (D7)")
    lines.append("")
    lines.append(f"Sinh boi `eval/capture_environment.py` luc {datetime.now().isoformat(timespec='seconds')}.")
    lines.append("")
    lines.append(
        "**Muc dich**: giup nguoi khac (hoac chinh nhom 6 thang sau) TAI LAP duoc ket qua "
        "trong `eval/REPORT.md`. Bat cu muc nao ghi `KHONG LAY DUOC` nghia la script khong "
        "the tu dong xac dinh tren may da chay - PHAI dien tay truoc khi coi tai lieu nay "
        "la day du."
    )
    lines.append("")

    lines.append("## He thong")
    lines.append("")
    for k, v in os_info.items():
        lines.append(f"- **{k}**: {v}")
    lines.append("")

    lines.append("## Python")
    lines.append("")
    for k, v in py_info.items():
        lines.append(f"- **{k}**: {v}")
    lines.append("")
    lines.append("### Toan bo package da cai (pip freeze)")
    lines.append("")
    lines.append("```")
    lines.append(pip_freeze)
    lines.append("```")
    lines.append("")

    lines.append("## Ollama")
    lines.append("")
    lines.append(f"- **Phien ban**: {ollama_info['ollama_version']}")
    lines.append("")
    if ollama_info["models"]:
        lines.append("### Model")
        lines.append("")
        for m, info in ollama_info["models"].items():
            lines.append(f"#### `{m}`")
            if isinstance(info, str):
                lines.append(f"- {info}")
            else:
                lines.append(f"- **digest (ID ngan trong 'ollama list')**: `{info['digest_id_ngan']}`")
                lines.append("- **`ollama show` output day du**:")
                lines.append("```")
                lines.append(info["ollama_show_output"])
                lines.append("```")
            lines.append("")
    else:
        lines.append("_Khong co model nao duoc chi dinh qua --models khi chay script nay._")
        lines.append("")

    lines.append("## Git")
    lines.append("")
    for k, v in git_info.items():
        lines.append(f"- **{k}**: {v}")
    if git_info.get("co_thay_doi_chua_commit", "").startswith("CO"):
        lines.append("")
        lines.append(
            "> ⚠️ Co thay doi CHUA COMMIT tai thoi diem chay eval - ket qua co the KHONG "
            "tai lap chinh xac 100% tu commit hash o tren. Nen commit truoc khi chay eval "
            "chinh thuc lan sau."
        )
    lines.append("")

    lines.append("## Seed (doc truc tiep tu source, luon dong bo voi code)")
    lines.append("")
    lines.append("| script | --seed mac dinh |")
    lines.append("|---|---|")
    for fname, seed in seeds.items():
        lines.append(f"| eval/{fname} | {seed} |")
    lines.append("")
    lines.append(
        "_Luu y: neu mot lan chay cu the truyen `--seed` khac gia tri mac dinh o tren, "
        "gia tri THAT SU DUNG trong lan chay do phai duoc ghi lai rieng (vd trong ten file "
        "ket qua hoac log lenh da chay), khong the suy ra tu bang nay._"
    )
    lines.append("")

    lines.append("---")
    lines.append(
        "_Chay lai `python3 eval/capture_environment.py --models <ten_model...> "
        "--out docs/environment.md` truoc MOI dot chay eval chinh thuc (D5), vi Ollama/"
        "model/package co the da duoc cap nhat ke tu lan truoc._"
    )
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--models", nargs="*", default=[],
                     help="Cac model Ollama can lay digest/thong tin, vd qwen2.5:3b qwen2.5:7b")
    ap.add_argument("--out", type=Path, default=Path("docs/environment.md"))
    ap.add_argument("--eval-dir", type=Path, default=Path("eval"))
    args = ap.parse_args()

    print("Dang thu thap thong tin moi truong...")
    os_info = get_os_info()
    py_info = get_python_info()
    pip_freeze = get_pip_freeze()
    git_info = get_git_info()
    ollama_info = get_ollama_info(args.models)
    seeds = extract_seeds_from_source(args.eval_dir)

    md = render_md(os_info, py_info, pip_freeze, git_info, ollama_info, seeds, args.models)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(md, encoding="utf-8")
    print(f"Da ghi: {args.out}")

    if "KHONG LAY DUOC" in ollama_info["ollama_version"]:
        print("[CANH BAO] Khong tim thay Ollama tren may dang chay script nay. Neu day KHONG "
              "phai may se chay eval that, hay chay lai script nay tren dung may do truoc khi "
              "coi docs/environment.md la day du cho D7.")


if __name__ == "__main__":
    main()
