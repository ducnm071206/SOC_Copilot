"""ui/components.py: các khối giao diện dùng chung (T3, T4, T5, T6, T8).

Quy tắc bắt buộc (T5): dữ liệu động chỉ đi qua st.code / st.dataframe (chuỗi thuần) / st.metric,
hoặc qua md_escape()/md_text() nếu dùng st.markdown. unsafe_allow_html chỉ dành cho CSS tĩnh và badge dựng
từ danh sách trắng trong ui/safe.py.
"""
from __future__ import annotations

import streamlit as st

from soc_copilot import storage

from . import backend, ticket
from .safe import (action_badge, fmt_duration, is_protected_ip, md_escape, md_text, sanitize_markdown,
                   severity_badge, status_badge, valid_ip)
from .styles import CSS
from .summary import default_priority, evidence, summarize

PRIORITIES = storage.PRIORITIES


# --------------------------------------------------------------------------- nền
def inject_css() -> None:
    st.markdown(f"<style>{CSS}</style>", unsafe_allow_html=True)   # CSS tĩnh, không chứa dữ liệu động


@st.cache_data(ttl=10, show_spinner=False)
def _health_cached() -> dict:
    return backend.health()


def _cb_recheck() -> None:
    _health_cached.clear()


def flash(kind: str, msg: str) -> None:
    st.session_state["_flash"] = (kind, msg)


def show_flash() -> None:
    f = st.session_state.pop("_flash", None)
    if f:
        kind, msg = f
        {"error": st.error, "warning": st.warning, "success": st.success}.get(kind, st.info)(md_escape(msg, 500))


def render_backend_banner() -> None:
    if not backend.is_real():
        err = backend.import_error()
        st.warning("Đang chạy bằng backend MÔ PHỎNG (chưa nạp được `soc_copilot.core`). Kết quả chỉ để thử giao diện, "
                   "không dùng cho đánh giá." + (f" Lý do: {md_escape(err, 300)}" if err else ""))


# --------------------------------------------------------------------------- sidebar
def render_sidebar() -> dict:
    """Trả về {model, mode, threshold}. Thanh trạng thái phản ánh kết nối Ollama thật."""
    with st.sidebar:
        st.markdown("## SOC Analyst Copilot")
        h = _health_cached()
        if h["ok"]:
            st.success("Ollama: đã kết nối" + (f" (v{md_escape(h['version'], 30)})" if h.get("version") else ""))
        else:
            st.error("Ollama: KHÔNG kết nối. " + md_escape(h.get("error") or "Hãy chạy `ollama serve`.", 300))
        st.button("Kiểm tra lại kết nối", key="recheck", on_click=_cb_recheck)

        models = h.get("models") or []
        model = None
        if models:
            default = backend.cfg("DEFAULT_MODEL", None)
            idx = models.index(default) if default in models else 0
            model = st.selectbox("Mô hình (đã pull)", models, index=idx, key="model")
        elif h["ok"]:
            st.warning("Chưa có mô hình nào. Chạy `ollama pull <tên mô hình>` rồi bấm kiểm tra lại.")

        mode, thr = "rag", float(backend.cfg("THRESHOLD", 0.45))
        with st.expander("Nâng cao"):
            mode = st.selectbox("Chế độ truy xuất", list(backend.MODES), format_func=lambda m: backend.MODES[m], key="mode")
            thr = st.slider("Ngưỡng khoảng cách cosine (RAG)", 0.05, 1.0, min(max(thr, 0.05), 1.0), 0.01, key="threshold",
                            help="Khoảng cách nhỏ hơn hoặc bằng ngưỡng thì dùng SOP top-1, ngược lại dùng SOP chung.")
        st.caption("Dữ liệu được xử lý hoàn toàn cục bộ. Không có lệnh nào được thực thi thật.")
    return {"model": model, "mode": mode, "threshold": thr, "ollama_ok": bool(h["ok"])}


# --------------------------------------------------------------------------- bảng tóm tắt đầu vào
def kv_table(rows: list[tuple[str, str]]) -> None:
    st.dataframe([{"Trường": k, "Giá trị": str(v)} for k, v in rows], hide_index=True, use_container_width=True)


def render_parse_summary(alert: dict) -> None:
    st.markdown("**Cảnh báo đã đọc được** (kiểm tra trước khi phân tích)")
    kv_table(summarize(alert))


# --------------------------------------------------------------------------- kết quả
def _num(v) -> str:
    try:
        return f"{float(v):.2f}"
    except (TypeError, ValueError):
        return "—"


def render_result(res: dict, alert: dict | None, key: str) -> None:
    if not res.get("ok", True) or res.get("error"):
        st.error("Phân tích gặp lỗi: " + md_escape(res.get("error") or "không rõ nguyên nhân", 500))
        if not res.get("attack_type") and not res.get("report_md"):
            return

    st.markdown("### " + md_escape(res.get("attack_type") or "Chưa xác định loại tấn công", 150))
    c1, c2, c3 = st.columns(3)
    c1.markdown(severity_badge(res.get("severity"), "LLM: "), unsafe_allow_html=True)
    c2.markdown(severity_badge(res.get("rule_severity"), "Theo rule.level: "), unsafe_allow_html=True)
    c3.markdown(action_badge(res.get("recommended_action"), "Đề xuất: "), unsafe_allow_html=True)

    if res.get("severity_mismatch"):
        st.warning("Mức nghiêm trọng do mô hình đánh giá lệch với mức suy ra từ rule.level. Hệ thống hiển thị cả hai; "
                   "analyst quyết định.")
    if res.get("suspected_injection"):
        st.warning("Nghi ngờ nội dung cảnh báo chứa lời chèn lệnh (prompt injection). Không tin kết quả này nếu chưa "
                   "đối chiếu với dữ liệu gốc.")
    if res.get("truncated"):
        st.warning("Prompt có thể đã bị cắt do vượt num_ctx, kết quả có thể thiếu thông tin.")

    if res.get("summary"):
        st.markdown("**Tóm tắt**")
        st.markdown(md_text(res["summary"], 3000))

    st.markdown("**SOP áp dụng**")
    d = res.get("sop_distance")
    kv_table([
        ("SOP", res.get("sop_id") or "—"),
        ("Khoảng cách cosine", f"{float(d):.3f}" if isinstance(d, (int, float)) else "—"),
        ("Dùng SOP chung (fallback)", "Có" if res.get("sop_is_fallback") else "Không"),
    ])
    alts = res.get("sop_alternatives") or []
    if alts:
        st.caption("SOP thay thế gần nhất")
        st.dataframe([{"SOP": str(a.get("sop_id", "")),
                       "Khoảng cách": f"{float(a['distance']):.3f}" if isinstance(a.get("distance"), (int, float)) else "—"}
                      for a in alts if isinstance(a, dict)], hide_index=True, use_container_width=True)

    st.markdown("**Hành động đề xuất**")
    ip = valid_ip(res.get("action_target_ip"))
    if res.get("recommended_action") == "BLOCK_IP" and ip:
        st.code(ip, language=None)
    if res.get("needs_human_confirm"):
        st.info("Hành động này cần người xác nhận trước khi thực hiện.")
    notes = [n for n in (res.get("guard_notes") or []) if n]
    if notes:
        st.info("Lớp kiểm tra (guard) đã can thiệp:\n\n" + "\n".join("- " + md_escape(n, 400) for n in notes))

    if alert is not None:
        ev = evidence(alert)
        if ev:
            with st.expander("Bằng chứng (dữ liệu gốc, hiển thị nguyên văn)", expanded=False):
                for label, text in ev:
                    st.caption(label)
                    st.code(text, language=None)

    if res.get("report_md"):
        with st.expander("Báo cáo phân tích", expanded=True):
            st.markdown(sanitize_markdown(res["report_md"]))
            st.caption("Nội dung do mô hình sinh. Ảnh và liên kết ngoài đã bị vô hiệu hoá.")

    t = res.get("timings") or {}
    meta = res.get("meta") or {}
    st.caption(
        f"Thời gian: truy xuất {_num(t.get('t_retrieve'))} s · LLM {_num(t.get('t_llm'))} s · tổng {_num(t.get('t_total'))} s"
        f" | Mô hình: {md_escape(meta.get('model'), 60)} · chế độ: {md_escape(meta.get('retrieval_mode'), 30)}"
        f" · prompt: {md_escape(meta.get('prompt_version'), 30)}")


# --------------------------------------------------------------------------- nút tương tác (T6)
def _cb_status(rec_id: int, status: str) -> None:
    try:
        storage.update_status(rec_id, status)
    except Exception as e:  # noqa: BLE001
        flash("error", f"Không cập nhật được trạng thái: {e}")


def _cb_priority(rec_id: int, widget_key: str) -> None:
    try:
        storage.update_priority(rec_id, st.session_state[widget_key])
    except Exception as e:  # noqa: BLE001
        flash("error", f"Không cập nhật được mức ưu tiên: {e}")


def _cb_show_block(state_key: str) -> None:
    st.session_state[state_key] = True


def render_actions(rec_id: int, res: dict, alert: dict | None, key: str) -> None:
    rec = storage.get_analysis(rec_id)
    if not rec:
        st.warning("Không tìm thấy bản ghi trong CSDL (có thể đã bị xoá).")
        return
    show_flash()
    status = rec["status"]
    prio = rec["priority"] or default_priority(res.get("severity"))

    st.markdown("**Trạng thái:** " + status_badge(status), unsafe_allow_html=True)
    cols = st.columns(4)
    cols[0].button("Xác nhận sự cố", key=f"{key}_ok_{rec_id}", on_click=_cb_status, args=(rec_id, "confirmed"),
                   disabled=status in ("confirmed", "resolved"), use_container_width=True)
    cols[1].button("Đánh dấu False Positive", key=f"{key}_fp_{rec_id}", on_click=_cb_status, args=(rec_id, "false_positive"),
                   disabled=status == "false_positive", use_container_width=True)
    cols[2].button("Đã xử lý xong", key=f"{key}_done_{rec_id}", on_click=_cb_status, args=(rec_id, "resolved"),
                   disabled=status != "confirmed", use_container_width=True)
    cols[3].button("Mở lại (Mới)", key=f"{key}_new_{rec_id}", on_click=_cb_status, args=(rec_id, "new"),
                   disabled=status == "new", use_container_width=True)

    pkey = f"{key}_prio_{rec_id}"
    st.selectbox("Mức ưu tiên (mặc định suy từ mức nghiêm trọng)", PRIORITIES,
                 index=PRIORITIES.index(prio) if prio in PRIORITIES else 2,
                 key=pkey, on_change=_cb_priority, args=(rec_id, pkey))

    ip = valid_ip(res.get("action_target_ip"))
    can_block = (res.get("recommended_action") == "BLOCK_IP" and ip is not None
                 and not is_protected_ip(ip, backend.cfg("PROTECTED_IPS", [])))
    bkey = f"{key}_block_{rec_id}"
    d1, d2, d3 = st.columns(3)
    d1.download_button("Tạo ticket (Markdown)", ticket.build_ticket_markdown(rec_id, res, alert, prio, status, rec["ts"]),
                       file_name=f"ticket_{rec_id}.md", mime="text/markdown", key=f"{key}_tmd_{rec_id}",
                       use_container_width=True)
    d2.download_button("Xuất JSON", ticket.build_ticket_json(rec_id, res, alert, prio, status, rec["ts"]),
                       file_name=f"ticket_{rec_id}.json", mime="application/json", key=f"{key}_tjs_{rec_id}",
                       use_container_width=True)
    d3.button("Đề xuất chặn IP", key=f"{key}_blk_{rec_id}", on_click=_cb_show_block, args=(bkey,), disabled=not can_block,
              help="Chỉ bật khi hành động đề xuất là BLOCK_IP, có IP hợp lệ và IP không thuộc danh sách được bảo vệ.",
              use_container_width=True)
    if st.session_state.get(bkey) and can_block:
        st.code(f"sudo iptables -I INPUT -s {ip} -j DROP", language="bash")   # ip đã qua ipaddress.ip_address()
    st.caption("Không có lệnh nào được thực thi thật. Người phân tích là người quyết định cuối cùng.")


# --------------------------------------------------------------------------- KPI (T8)
def render_kpis() -> None:
    try:
        k = storage.kpis()
    except Exception as e:  # noqa: BLE001
        st.error("Không đọc được thống kê: " + md_escape(e, 300))
        return
    a = st.columns(4)
    a[0].metric("Tổng lượt phân tích", k["total"])
    a[1].metric("Đã xác nhận", k["confirmed"])
    a[2].metric("Đã xử lý xong", k["resolved"])
    a[3].metric("False Positive", k["false_positive"])
    b = st.columns(3)
    b[0].metric("Thời gian phân tích TB", fmt_duration(k["avg_analysis_s"]),
                help="Thời gian chạy pipeline (truy xuất + LLM + guard). Không phải MTTR.")
    b[1].metric("MTTA", fmt_duration(k["mtta_s"]), help="Trung bình từ lúc tạo bản ghi đến lúc analyst bấm 'Xác nhận sự cố'.")
    b[2].metric("MTTR", fmt_duration(k["mttr_s"]), help="Trung bình từ lúc tạo bản ghi đến lúc bấm 'Đã xử lý xong'.")
