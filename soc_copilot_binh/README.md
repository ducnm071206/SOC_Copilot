# SOC Copilot

Trợ lý phân tích cảnh báo Wazuh chạy hoàn toàn nội bộ: SOP (Markdown) → Chroma → Ollama → guard kiểm tra hành động.

## Yêu cầu
- Python 3.10–3.12
- [Ollama](https://ollama.com) phiên bản **>= 0.5** (cần cho JSON schema); kiểm tra: `ollama --version`

## Cài đặt (Windows PowerShell)
```powershell
.\scripts\setup.ps1          # hoặc làm tay bên dưới
```
Làm tay:
```powershell
py -m venv venv
venv\Scripts\Activate.ps1     # nếu bị chặn: Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
pip install -r requirements.txt
ollama pull qwen2.5:7b        # đổi theo config.DEFAULT_MODEL
```
Linux/macOS: `bash scripts/setup.sh`.

## Chạy lần đầu (cần mạng)
Lần đầu chạy cần mạng để tải model embedding từ HuggingFace (`config.EMBED_MODEL`) vào cache.
```powershell
python -m soc_copilot.cli sync      # nạp data/sops/*.md vào Chroma
python -m soc_copilot.cli health    # kiểm tra Ollama và danh sách model
python -m soc_copilot.cli analyze data\samples\test.json
```
Tuỳ chọn: `--model`, `--mode rag|rule_map|full_context`, `--threshold`.

## Chạy offline (các lần sau)
```powershell
$env:HF_HUB_OFFLINE = "1"; $env:TRANSFORMERS_OFFLINE = "1"
python -m soc_copilot.cli analyze data\samples\test.json
```
Bash: `export HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1`.

## Thêm / sửa SOP
Sửa file trong `data/sops/*.md` (front matter: `id`, `title`, `category`, `default_severity`), rồi chạy `sync`
(tự động chạy khi khởi động). File bị xoá sẽ biến mất khỏi Chroma. Bắt buộc có `sop_general`.
Nếu đổi `EMBED_MODEL`: xoá thư mục `chroma_data/` rồi `sync` lại (chương trình sẽ báo lỗi nếu lệch).

## Chạy test
```powershell
pytest -q
```
Không cần Ollama hay tải model (LLM và embedding được giả lập).

## Chạy eval
TODO (phần đánh giá do Đức phụ trách): cập nhật lệnh tại đây khi có `eval/`.

## Kiểm chứng dữ liệu không rời hạ tầng
```powershell
python scripts\egress_check.py              # lần 1
python scripts\egress_check.py --offline    # lần 2
```
Xem `docs/B9_egress_checklist.md` cho phần Wireshark, Streamlit và font ngoài.

## Cấu trúc
```
soc_copilot/  config, models, features, sop_store, retrieval, prompts, llm, guard, core, cli, netguard
data/sops/    SOP dạng Markdown      data/samples/  alert mẫu      tests/  pytest
```
Lưu ý: ngưỡng của guard và `LEVEL_BUCKETS` là chính sách của nhóm, không phải chuẩn Wazuh.
