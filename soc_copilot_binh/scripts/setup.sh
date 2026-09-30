#!/usr/bin/env bash
set -e
cd "$(dirname "$0")/.."
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
if command -v ollama >/dev/null; then
  echo "Ollama: $(ollama --version)  (cần >= 0.5)"
  MODEL=$(python -c "from soc_copilot import config; print(config.DEFAULT_MODEL)")
  ollama pull "$MODEL"
else
  echo "CHƯA có ollama, cài từ https://ollama.com"
fi
python -m soc_copilot.cli sync
pytest -q
echo "Xong. Kích hoạt venv: source venv/bin/activate"
