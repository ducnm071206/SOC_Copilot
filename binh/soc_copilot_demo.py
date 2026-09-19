"""
Chạy demo: python soc_copilot_demo.py
Yêu cầu: Ollama đang chạy (ollama serve) với model qwen2.5 đã pull.
Cần thư mục wazuh_samples/ (chứa mau*.json) nằm cùng cấp với file này.
"""
import json
import os

import chromadb
import requests
from pydantic import BaseModel, Field

CHROMA_PATH = "chroma_sop_db"
OLLAMA_MODEL = "qwen2.5"
FALLBACK_DISTANCE_THRESHOLD = 0.45
FALLBACK_SOP_ID = "sop_general"
SAMPLES_DIR = "wazuh_samples"

# ============================================================
# 1. KNOWLEDGE BASE (SOP) — thêm loại tấn công mới: thêm 1 entry vào list này
# ============================================================
SOPS = [
    {
        "id": "sop_ssh_bruteforce",
        "text": (
            "SOP Xử lý SSH Brute Force / đăng nhập sai liên tục: (1) kiểm tra auth.log "
            "xác định số lần thử và khoảng thời gian, (2) chặn IP nguồn bằng iptables "
            "hoặc active-response trên Wazuh, (3) nếu có đăng nhập thành công sau chuỗi "
            "thất bại, khóa ngay tài khoản (passwd -l) và buộc đổi mật khẩu, (4) khuyến "
            "nghị tắt đăng nhập root qua SSH, chuyển sang xác thực SSH key."
        ),
        "metadata": {"category": "Brute Force", "severity": "High"},
    },
    {
        "id": "sop_sqli",
        "text": (
            "SOP Xử lý SQL Injection: (1) kiểm tra log ứng dụng web xác định payload và "
            "endpoint bị nhắm tới, (2) xác định database có bị truy xuất trái phép/rò rỉ "
            "dữ liệu không, (3) chặn IP tấn công trên WAF/Nginx (deny <srcip>;), (4) yêu "
            "cầu vá endpoint bằng Prepared Statements/ORM thay vì nối chuỗi SQL thủ công."
        ),
        "metadata": {"category": "Web Attack", "severity": "Critical"},
    },
    {
        "id": "sop_xss",
        "text": (
            "SOP Xử lý Cross-Site Scripting (XSS): (1) xác định payload, endpoint, phân "
            "biệt stored hay reflected XSS, (2) chặn IP nguồn nếu đang tấn công, (3) yêu "
            "cầu vá bằng encode/escape output và áp dụng Content-Security-Policy, (4) rà "
            "soát dữ liệu người dùng khác để loại trừ payload đã lưu trữ (stored XSS)."
        ),
        "metadata": {"category": "Web Attack", "severity": "High"},
    },
    {
        "id": "sop_web_bruteforce_scan",
        "text": (
            "SOP Xử lý Web Brute Force / Vulnerability Scanning: (1) xác nhận hành vi dò "
            "quét tự động qua tốc độ/số lượng request lỗi 400/404, (2) chặn tạm IP nguồn "
            "ở WAF/reverse proxy, (3) rà soát request trả về 200/302 bất thường để điều "
            "tra sâu, (4) theo dõi IP này ở các cảnh báo tiếp theo vì quét thường là bước "
            "trinh sát trước tấn công cụ thể hơn."
        ),
        "metadata": {"category": "Reconnaissance", "severity": "Medium"},
    },
    {
        "id": "sop_port_scan",
        "text": (
            "SOP Xử lý Port Scanning: (1) xác định IP nguồn, dải cổng bị quét và tốc độ "
            "quét để phân biệt quét thủ công/tự động (Nmap...), (2) chặn tạm IP nguồn ở "
            "firewall nếu quét liên tục/diện rộng, (3) rà soát các cổng dịch vụ đang mở "
            "không cần thiết và đóng bớt bề mặt tấn công, (4) theo dõi các alert tiếp "
            "theo từ IP này vì quét cổng thường là bước trinh sát ban đầu."
        ),
        "metadata": {"category": "Reconnaissance", "severity": "Medium"},
    },
    {
        "id": "sop_file_integrity",
        "text": (
            "SOP Xử lý File Integrity Monitoring (FIM) — file bị thêm/sửa bất thường: (1) "
            "xác định đường dẫn, chủ sở hữu, hash file để đánh giá mức nhạy cảm (web "
            "root, cron, thư mục hệ thống), (2) nếu nghi webshell/mã độc, cô lập máy chủ, "
            "diệt tiến trình (kill -9 <PID>) và giữ file để phân tích, (3) đối chiếu lịch "
            "bảo trì/deploy hợp lệ để loại trừ thay đổi chính đáng, (4) rà soát log truy "
            "cập quanh thời điểm thay đổi để xác định nguồn gốc."
        ),
        "metadata": {"category": "File Integrity", "severity": "High"},
    },
    {
        "id": "sop_privilege_escalation",
        "text": (
            "SOP Xử lý Privilege Escalation: (1) xác định tài khoản, tiến trình liên quan "
            "và kiểm tra hành động có được phê duyệt không, (2) nếu trái phép, khóa ngay "
            "tài khoản và thu hồi quyền vừa được cấp, (3) cô lập máy chủ nếu nghi ngờ đã "
            "bị khai thác lỗ hổng leo thang, (4) rà soát toàn bộ hành động của tài khoản "
            "trong phiên đó, vá lỗ hổng nếu có."
        ),
        "metadata": {"category": "Privilege Escalation", "severity": "Critical"},
    },
    {
        "id": "sop_malware",
        "text": (
            "SOP Xử lý Malware (bao gồm phát hiện chữ ký test như EICAR): (1) cô lập máy "
            "chủ/máy trạm khỏi mạng ngay lập tức, (2) xác định tiến trình/file liên quan, "
            "giữ mẫu để phân tích thay vì xóa vội, (3) quét toàn hệ thống bằng "
            "antivirus/ClamAV tìm file liên quan khác, (4) xác định vector lây nhiễm "
            "(email, USB, tải xuống) để ngăn tái diễn, (5) khôi phục từ bản sao lưu sạch "
            "nếu cần."
        ),
        "metadata": {"category": "Malware", "severity": "Critical"},
    },
    {
        "id": "sop_ddos",
        "text": (
            "SOP Xử lý DDoS / Flooding: (1) xác định loại lưu lượng bất thường (số lượng "
            "request/giây, giao thức) và nguồn gốc (một IP hay botnet phân tán), (2) kích "
            "hoạt rate-limiting hoặc chặn IP/subnet nguồn tại firewall hoặc CDN, (3) nếu "
            "quy mô lớn, kích hoạt dịch vụ chống DDoS của nhà cung cấp hạ tầng, (4) theo "
            "dõi tài nguyên hệ thống (CPU, băng thông) để đánh giá mức ảnh hưởng dịch vụ."
        ),
        "metadata": {"category": "Availability", "severity": "High"},
    },
    {
        "id": "sop_ransomware",
        "text": (
            "SOP Xử lý Ransomware: (1) cô lập ngay lập tức máy bị nhiễm khỏi mạng (rút "
            "cáp/tắt Wi-Fi) để chặn lây lan sang các máy khác, (2) không tắt máy nếu cần "
            "giữ bằng chứng điều tra trong RAM, (3) xác định tiến trình mã hóa và dừng "
            "nếu còn đang chạy, (4) kiểm tra bản sao lưu sạch gần nhất để khôi phục, (5) "
            "không tự ý trả tiền chuộc, báo cáo sự cố lên cấp quản lý/cơ quan chức năng "
            "theo quy trình của tổ chức."
        ),
        "metadata": {"category": "Malware", "severity": "Critical"},
    },
    {
        "id": "sop_general",
        "text": (
            "SOP Xử lý dự phòng — Ứng phó sự cố an ninh chung (tham chiếu NIST SP "
            "800-61), áp dụng khi không có SOP chuyên biệt phù hợp: (1) CONTAINMENT — "
            "chặn IP nguồn nghi vấn, lưu log thô làm bằng chứng, (2) ERADICATION — quét "
            "antivirus, kiểm tra tiến trình/cổng dịch vụ lạ (ss -tulpn), (3) RECOVERY — vá "
            "lỗ hổng, đổi mật khẩu quản trị, khôi phục dịch vụ, (4) LESSONS LEARNED — ghi "
            "nhận sự cố và cập nhật quy trình."
        ),
        "metadata": {"category": "General", "severity": "Medium"},
    },
]


def init_vector_db():
    client = chromadb.PersistentClient(path=CHROMA_PATH)
    collection = client.get_or_create_collection(name="soc_sops")
    collection.upsert(
        documents=[s["text"] for s in SOPS],
        metadatas=[s["metadata"] for s in SOPS],
        ids=[s["id"] for s in SOPS],
    )
    return collection


def retrieve_sop_for_alert(collection, wazuh_alert: dict):
    rule = wazuh_alert.get("rule", {})
    query = " ".join(
        part
        for part in [
            rule.get("description", ""),
            " ".join(rule.get("groups", [])),
            " ".join(rule.get("mitre", {}).get("technique", [])),
        ]
        if part
    ) or json.dumps(wazuh_alert)[:500]

    results = collection.query(query_texts=[query], n_results=1)
    if results["documents"][0]:
        doc, meta, dist, doc_id = (
            results["documents"][0][0],
            results["metadatas"][0][0],
            results["distances"][0][0],
            results["ids"][0][0],
        )
        if dist <= FALLBACK_DISTANCE_THRESHOLD:
            return {"text": doc, "source": doc_id, "distance": dist}

    fb = collection.get(ids=[FALLBACK_SOP_ID])
    return {"text": fb["documents"][0], "source": f"{FALLBACK_SOP_ID} (fallback)", "distance": 2.0}


# ============================================================
# 2. CORE LOGIC — gọi Ollama với SOP đã truy xuất (RAG)
# ============================================================
class SOCAnalysisResult(BaseModel):
    attack_type: str = Field(description="Tên loại tấn công/hành vi, ví dụ: SSH Brute Force, SQL Injection")
    severity: str = Field(description="Mức độ nghiêm trọng: Low, Medium, High, Critical")
    summary: str = Field(description="Tóm tắt ngắn gọn sự kiện cảnh báo")
    recommended_action: str = Field(description="Hành động đề xuất: BLOCK_IP, ISOLATE_HOST hoặc REVIEW_LOG")
    sop_source: str = Field(description="ID của SOP dùng làm căn cứ")


def analyze_alert_with_ai(wazuh_alert_json: str, sop_context: dict):
    url = "http://localhost:11434/api/chat"
    prompt = f"""
    Bạn là SOC Analyst Copilot. Phân tích cảnh báo Wazuh sau, DỰA TRÊN SOP bên dưới,
    và trích xuất thông tin theo schema JSON. "recommended_action" và "summary" phải
    bám sát SOP, không tự bịa quy trình khác.

    [SOP tham chiếu — nguồn: {sop_context['source']}]:
    {sop_context['text']}

    [Wazuh Alert Content]:
    {wazuh_alert_json}
    """
    payload = {
        "model": OLLAMA_MODEL,
        "messages": [
            {
                "role": "system",
                "content": (
                    f"You must output valid JSON matching this schema: "
                    f"{SOCAnalysisResult.model_json_schema()}. "
                    f"Set sop_source to exactly: {sop_context['source']}"
                ),
            },
            {"role": "user", "content": prompt},
        ],
        "format": "json",
        "stream": False,
    }
    response = requests.post(url, json=payload)
    if response.status_code != 200:
        raise Exception(f"Lỗi từ Ollama: {response.text}")
    return SOCAnalysisResult.model_validate_json(response.json()["message"]["content"])


# ============================================================
# 3. CHẠY DEMO
# ============================================================
if __name__ == "__main__":
    if not os.path.exists(SAMPLES_DIR):
        print(f"Chưa tìm thấy thư mục '{SAMPLES_DIR}'.")
    else:
        collection = init_vector_db()
        files = sorted(f for f in os.listdir(SAMPLES_DIR) if f.startswith("mau") and f.endswith(".json"))
        print(f"=> {len(files)} file mẫu. Bắt đầu truy xuất SOP + phân tích...\n")

        for file_name in files:
            path = os.path.join(SAMPLES_DIR, file_name)
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()

            print(f"--- {file_name} ---")
            try:
                alert = json.loads(content)
                sop_context = retrieve_sop_for_alert(collection, alert)
                print(f"SOP: {sop_context['source']} (distance={sop_context['distance']:.4f})")
                result = analyze_alert_with_ai(content, sop_context)
                print(json.dumps(result.model_dump(), indent=2, ensure_ascii=False))
            except Exception as e:
                print(f"Lỗi: {e}")
            print()
