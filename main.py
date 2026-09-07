import os
import json
import requests
from pydantic import BaseModel, Field

# 1. Định nghĩa cấu trúc chuẩn đầu ra của AI
class SOCAnalysisResult(BaseModel):
    attack_type: str = Field(description="Tên loại tấn công hoặc hành vi (ví dụ: SSH Brute Force, SQL Injection, FIM...)")
    severity: str = Field(description="Mức độ nghiêm trọng: Low, Medium, High, Critical")
    summary: str = Field(description="Tóm tắt ngắn gọn sự kiện cảnh báo")
    recommended_action: str = Field(description="Hành động đề xuất: BLOCK_IP, ISOLATE_HOST hoặc REVIEW_LOG")

# 2. Hàm gọi Ollama (Qwen2.5) để phân tích nội dung alert
def analyze_alert_with_ai(wazuh_alert_json: str):
    url = "http://localhost:11434/api/chat"
    
    prompt = f"""
    Bạn là một SOC Analyst Copilot thông minh. Hãy phân tích cảnh báo Wazuh sau đây và trích xuất thông tin theo cấu trúc JSON yêu cầu:
    [Wazuh Alert Content]:
    {wazuh_alert_json}
    """

    payload = {
        "model": "qwen2.5",
        "messages": [
            {
                "role": "system", 
                "content": f"You are a cybersecurity assistant. You must output valid JSON strictly matching this schema: {SOCAnalysisResult.model_json_schema()}"
            },
            {"role": "user", "content": prompt}
        ],
        "format": "json",
        "stream": False
    }

    response = requests.post(url, json=payload)
    
    if response.status_code == 200:
        result_content = response.json()["message"]["content"]
        parsed_data = SOCAnalysisResult.model_validate_json(result_content)
        return parsed_data
    else:
        raise Exception(f"Lỗi từ Ollama: {response.text}")

# 3. Chương trình chính: Quét 12 file mẫu và nhờ AI phân tích
if __name__ == "__main__":
    samples_dir = "wazuh_samples"
    
    if not os.path.exists(samples_dir):
        print(f"Chưa tìm thấy thư mục '{samples_dir}'.")
    else:
        files = [f for f in os.listdir(samples_dir) if f.startswith("mau") and f.endswith(".json")]
        print(f"=> Tìm thấy {len(files)} file mẫu alert từ Đức. Bắt đầu gửi cho AI phân tích...\n")

        for file_name in files:
            file_path = os.path.join(samples_dir, file_name)
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
            
            print(f"--------------------------------------------------")
            print(f"Đang xử lý file: {file_name}")
            
            try:
                # Gọi AI phân tích
                analysis_result = analyze_alert_with_ai(content)
                
                # In kết quả dạng JSON đẹp mắt
                print(json.dumps(analysis_result.model_dump(), indent=4, ensure_ascii=False))
            except Exception as e:
                print(f"Lỗi xử lý file {file_name}: {e}")