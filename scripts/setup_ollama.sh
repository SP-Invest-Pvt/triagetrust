#!/usr/bin/env bash
# Free local model, no API key. Needs ~6 GB disk; 16 GB RAM recommended.
set -euo pipefail
MODEL=${MODEL:-qwen2.5-coder:7b}
if ! command -v ollama >/dev/null; then
  if [ "$(uname)" = "Darwin" ]; then brew install ollama; else curl -fsSL https://ollama.com/install.sh | sh; fi
fi
(ollama serve >/dev/null 2>&1 &) ; sleep 3
ollama pull "$MODEL"
echo "Ready. Run: PROVIDER=ollama MODEL=$MODEL ./scripts/run_all.sh"
