# Free local model on Windows, no API key.
param([string]$Model = "qwen2.5-coder:7b")
if (-not (Get-Command ollama -ErrorAction SilentlyContinue)) { winget install --id Ollama.Ollama -e --accept-source-agreements --accept-package-agreements }
Start-Process ollama -ArgumentList "serve" -WindowStyle Hidden; Start-Sleep 3
ollama pull $Model
Write-Host "Ready. Run: .\scripts\run_all.ps1 -Provider ollama -Model $Model"
