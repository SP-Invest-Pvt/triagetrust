#!/usr/bin/env bash
# Download the OWASP Benchmark (labelled Java test cases + historical scanner results) into data/.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p data
if [ ! -d data/BenchmarkJava-master ]; then
  curl -sSL -o data/bench.zip https://codeload.github.com/OWASP-Benchmark/BenchmarkJava/zip/refs/heads/master
  (cd data && unzip -q bench.zip && rm bench.zip)
fi
echo "OWASP Benchmark ready in data/BenchmarkJava-master"
