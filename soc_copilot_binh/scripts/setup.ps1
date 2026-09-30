$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")
py -m venv venv
& .\venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
if (Get-Command ollama -ErrorAction SilentlyContinue) {
    ollama --version
    $model = python -c "from soc_copilot import config; print(config.DEFAULT_MODEL)"
    ollama pull $model
} else {
    Write-Host "CHUA co ollama, cai tu https://ollama.com"
}
python -m soc_copilot.cli sync
pytest -q
Write-Host "Xong."
