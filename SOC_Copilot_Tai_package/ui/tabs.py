"""ui/tabs.py: hai tab chính: Phân tích và Lịch sử (T3, T4, T7)."""
from __future__ import annotations

import json
from pathlib import Path

import streamlit as st

from soc_copilot import storage

from . import backend, components as C
from .safe import md_escape
from .summary import alert_label, default_priority, parse_alert_text, unwrap, validate_alert

ROOT = Path(__file__).resolve().parents[1]
SAMPLES_DIR = ROOT / "data" / "samples"
MAX_UPLOAD_BYTES = 30 * 1024 * 1024      # file alert lớn (vài chục MB) vẫn nạp được
MAX_LOADED_ALERTS = 2000                 # chỉ đưa tối đa từng này cảnh báo vào danh sách chọn


def _dump(alert: dict) -> str:
    return json.dumps(alert, ensure_ascii=False, indent=2, default=str)


# --------------------------------------------------------------------------- callback nạp dữ liệu
def list_samples() -> list[str]:
    try:
        return sorted(p.name for p in SAMPLES_DIR.glob("*.json") if p.is_file())
    except OSError:
        return []


def _cb_load_sample() -> None:
    name = st.session_state.get("sample_pick") or ""
    if not name:
        return
    p = (SAMPLES_DIR / name).resolve()
    if p.parent != SAMPLES_DIR.resolve() or not p.is_file():
        C.flash("error", "Tên file mẫu không hợp lệ.")
        return
    try:
        st.session_state["alert_text"] = p.read_text(encoding="utf-8-sig")[:MAX_UPLOAD_BYTES]
        st.session_state["loaded"] = []
    except OSError as e:
        C.flash("error", f"Không đọc được file mẫu: {e}")


def _cb_load_upload() -> None:
    f = st.session_state.get("upload")
    if f is None:
        return
    data = f.getvalue()
    if len(data) > MAX_UPLOAD_BYTES:
        C.flash("error", f"File quá lớn ({len(data) // (1024 * 1024)} MB, tối đa {MAX_UPLOAD_BYTES // (1024 * 1024)} MB).")
        return
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        C.flash("error", "File không phải văn bản UTF-8.")
        return
    alerts, err = parse_alert_text(text, max_alerts=MAX_LOADED_ALERTS)
    if err:
        C.flash("error", err)
        return
    if not alerts:
        C.flash("warning", "File không chứa cảnh báo nào.")
        return
    st.session_state["loaded"] = alerts if len(alerts) > 1 else []
    st.session_state["alert_text"] = _dump(alerts[0])
    st.session_state["loaded_idx"] = 0
    if len(alerts) >= MAX_LOADED_ALERTS:
        C.flash("warning", f"Chỉ nạp {MAX_LOADED_ALERTS} cảnh báo đầu. Dùng eval/extract_samples.py để trích mẫu từ file lớn.")


def _cb_pick_loaded() -> None:
    alerts = st.session_state.get("loaded") or []
    i = st.session_state.get("loaded_idx", 0)
    if isinstance(i, int) and 0 <= i < len(alerts):
        st.session_state["alert_text"] = _dump(alerts[i])


def _cb_clear_result() -> None:
    st.session_state.pop("last", None)


# --------------------------------------------------------------------------- tab Phân tích
def analyze_tab(cfg: dict) -> None:
    C.render_backend_banner()
    C.show_flash()
    st.subheader("Nhập cảnh báo Wazuh (JSON)")

    c1, c2 = st.columns(2)
    samples = list_samples()
    with c1:
        if samples:
            st.selectbox("Chọn mẫu có sẵn (data/samples)", [""] + samples, format_func=lambda v: v or "(chưa chọn)",
                         key="sample_pick", on_change=_cb_load_sample)
        else:
            st.caption("Chưa có mẫu trong data/samples/.")
    with c2:
        st.file_uploader("Hoặc tải file .json / .jsonl", type=["json", "jsonl"], key="upload", on_change=_cb_load_upload)

    loaded = st.session_state.get("loaded") or []
    if loaded:
        st.selectbox(f"Cảnh báo trong file ({len(loaded)})", range(len(loaded)),
                     format_func=lambda i: alert_label(loaded[i], i), key="loaded_idx", on_change=_cb_pick_loaded)

    st.text_area("Dán JSON của cảnh báo (một đối tượng, một mảng, hoặc JSON Lines)", key="alert_text", height=260)

    alerts, err = parse_alert_text(st.session_state.get("alert_text", ""))
    alert = None
    if err:
        st.error(md_escape(err, 300))
    elif len(alerts) > 1:
        i = st.selectbox(f"Phát hiện {len(alerts)} cảnh báo, chọn một để phân tích", range(len(alerts)),
                         format_func=lambda k: alert_label(alerts[k], k), key=f"alert_idx_{len(alerts)}")
        alert = alerts[i]
    elif alerts:
        alert = alerts[0]

    verr = validate_alert(alert) if alert is not None else None
    if verr:
        st.error(verr)
    elif alert is not None:
        C.render_parse_summary(alert)

    valid = alert is not None and not verr
    can_run = bool(valid and cfg.get("model") and cfg.get("ollama_ok", True))
    if valid and not can_run:
        st.warning("Chưa thể phân tích: Ollama chưa kết nối hoặc chưa chọn được mô hình (xem thanh bên).")

    if st.button("Phân tích", type="primary", key="btn_analyze", disabled=not can_run):
        with st.spinner("Đang truy xuất SOP và gọi mô hình cục bộ…"):
            res = backend.analyze(alert, cfg.get("model"), cfg.get("mode", "rag"), float(cfg.get("threshold", 0.45)))
        rec_id = None
        try:
            rec_id = storage.insert_analysis(alert, res, default_priority(res.get("severity")))
        except Exception as e:  # noqa: BLE001
            st.error("Không lưu được vào lịch sử: " + md_escape(e, 300))
        st.session_state["last"] = {"id": rec_id, "alert": alert, "result": res}

    # Luôn render từ session_state (không render trong nhánh của nút bấm)
    last = st.session_state.get("last")
    if last:
        st.divider()
        head, clear = st.columns([5, 1])
        rule_obj = unwrap(last["alert"]).get("rule")
        rule = rule_obj.get("id", "?") if isinstance(rule_obj, dict) else "?"
        head.caption(f"Kết quả của lần phân tích gần nhất (rule {md_escape(rule, 20)})")
        clear.button("Xoá kết quả", key="btn_clear", on_click=_cb_clear_result)
        C.render_result(last["result"], last["alert"], key="cur")
        if last["id"] is not None:
            st.divider()
            C.render_actions(last["id"], last["result"], last["alert"], key="cur")


# --------------------------------------------------------------------------- tab Lịch sử
_ALL = "Tất cả"


def _cb_delete_one(rec_id: int) -> None:
    try:
        storage.delete_analyses([rec_id])
        C.flash("success", f"Đã xoá bản ghi #{rec_id}.")
    except Exception as e:  # noqa: BLE001
        C.flash("error", f"Không xoá được: {e}")
    st.session_state["hist_del_ok"] = False


def _cb_delete_all() -> None:
    try:
        n = storage.delete_all()
        C.flash("success", f"Đã xoá {n} bản ghi.")
    except Exception as e:  # noqa: BLE001
        C.flash("error", f"Không xoá được: {e}")
    st.session_state["hist_del_ok"] = False


def history_tab() -> None:
    st.subheader("Lịch sử phân tích")
    C.render_kpis()
    st.divider()

    f1, f2, f3, f4 = st.columns(4)
    status = f1.selectbox("Trạng thái", [_ALL, *storage.STATUSES], key="hist_status")
    sev = f2.selectbox("Mức (LLM)", [_ALL, "Low", "Medium", "High", "Critical"], key="hist_sev")
    try:
        rules = storage.distinct_rule_ids()
    except Exception:  # noqa: BLE001
        rules = []
    rule = f3.selectbox("Rule", [_ALL, *rules], key="hist_rule")
    q = f4.text_input("Tìm (IP, loại tấn công, SOP)", key="hist_q")

    try:
        rows = storage.list_analyses(status=None if status == _ALL else status, severity=None if sev == _ALL else sev,
                                     rule_id=None if rule == _ALL else rule, q=q or None, limit=500)
    except Exception as e:  # noqa: BLE001
        st.error("Không đọc được lịch sử: " + md_escape(e, 300))
        return
    if not rows:
        st.info("Chưa có bản ghi nào khớp bộ lọc.")
        return

    def s(v):
        return "" if v is None else str(v)

    st.dataframe([{
        "ID": r["id"], "Thời điểm (UTC)": s(r["ts"]), "Rule": s(r["rule_id"]), "IP": s(r["srcip"]),
        "Loại": s(r["attack_type"]), "Mức (LLM)": s(r["severity"]), "Mức (rule)": s(r["rule_severity"]),
        "SOP": s(r["sop_id"]), "Khoảng cách": f"{r['distance']:.3f}" if isinstance(r["distance"], (int, float)) else "",
        "Hành động": s(r["action"]), "Trạng thái": s(r["status"]), "Ưu tiên": s(r["priority"]), "Mô hình": s(r["model"]),
    } for r in rows], hide_index=True, use_container_width=True)
    st.download_button("Xuất CSV (các dòng đang lọc)", storage.to_csv(rows), file_name="lich_su_phan_tich.csv",
                       mime="text/csv", key="hist_csv")

    st.divider()
    by_id = {r["id"]: r for r in rows}
    rec_id = st.selectbox("Xem chi tiết bản ghi", list(by_id), key="hist_pick",
                          format_func=lambda i: f"#{i}  rule {s(by_id[i]['rule_id'])}  {s(by_id[i]['attack_type'])[:50]}")
    rec = storage.get_analysis(rec_id)
    if rec:
        C.render_result(rec["result"], rec["alert"], key="hist")
        st.divider()
        C.render_actions(rec_id, rec["result"], rec["alert"], key="hist")

    with st.expander("Xoá dữ liệu"):
        st.checkbox("Tôi hiểu: thao tác xoá không thể hoàn tác", key="hist_del_ok")
        ok = bool(st.session_state.get("hist_del_ok"))
        d1, d2 = st.columns(2)
        d1.button("Xoá bản ghi đang xem", key="hist_del_one", on_click=_cb_delete_one, args=(rec_id,), disabled=not ok)
        d2.button("Xoá TOÀN BỘ lịch sử", key="hist_del_all", on_click=_cb_delete_all, disabled=not ok)
