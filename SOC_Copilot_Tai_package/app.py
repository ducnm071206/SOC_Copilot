"""app.py: điểm vào của dashboard (Tài). Giữ mỏng: chỉ lắp ráp; logic nằm trong ui/ và soc_copilot/.

Chạy:  streamlit run app.py
"""
import streamlit as st

from soc_copilot import storage
from ui import components as C
from ui import tabs

st.set_page_config(page_title="SOC Analyst Copilot", page_icon="🛡️", layout="wide")
C.inject_css()

try:
    storage.init_db()
except Exception as e:  # noqa: BLE001
    st.error(f"Không khởi tạo được cơ sở dữ liệu lịch sử: {e}")

cfg = C.render_sidebar()

st.title("SOC Analyst Copilot")
st.caption("Trợ lý phân tích cảnh báo Wazuh dùng RAG và LLM cục bộ (Ollama). Đề xuất chỉ mang tính tham khảo, "
           "người phân tích là người quyết định cuối cùng.")

tab_analyze, tab_history = st.tabs(["Phân tích", "Lịch sử"])
with tab_analyze:
    tabs.analyze_tab(cfg)
with tab_history:
    tabs.history_tab()
