"""Minimal, dependency-free LLM clients.

Every provider takes (system, user) text and returns the model's text. Responses are cached on
disk keyed by (provider, model, prompt, run), so an interrupted evaluation resumes where it
stopped and a re-run costs nothing.

Providers
  gemini     GEMINI_API_KEY (or GOOGLE_API_KEY)     default model gemini-2.5-flash
  anthropic  ANTHROPIC_API_KEY                      default model claude-haiku-4-5
  openai     OPENAI_API_KEY, OPENAI_BASE_URL         default model gpt-4o-mini
  ollama     OLLAMA_BASE_URL (http://localhost:11434) default model qwen2.5-coder:7b
Override the model with --model or TRIAGETRUST_MODEL.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path

DEFAULT_MODELS = {
    "gemini": "gemini-2.5-flash",
    "anthropic": "claude-haiku-4-5",
    "openai": "gpt-4o-mini",
    "ollama": "qwen2.5-coder:7b",
}


class ProviderError(RuntimeError):
    pass


def _post(url: str, body: dict, headers: dict, timeout: int = 120) -> dict:
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json", **headers})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


class Provider:
    name = "base"

    def __init__(self, model: str | None = None, temperature: float = 0.2,
                 cache_dir: str | Path = ".cache/llm", max_retries: int = 5):
        self.model = model or os.getenv("TRIAGETRUST_MODEL") or DEFAULT_MODELS.get(self.name, "")
        self.temperature = temperature
        self.cache_dir = Path(cache_dir)
        self.max_retries = max_retries

    # -- implemented by subclasses -------------------------------------------------------
    def _call(self, system: str, user: str) -> str:  # pragma: no cover - network
        raise NotImplementedError

    # -- shared ------------------------------------------------------------------------------
    def complete(self, system: str, user: str, run: int = 0) -> str:
        key = hashlib.sha256(json.dumps([self.name, self.model, self.temperature, system, user, run]).encode()).hexdigest()
        path = self.cache_dir / self.name / f"{key}.json"
        if path.exists():
            return json.loads(path.read_text())["text"]
        delay = 2.0
        for attempt in range(self.max_retries):
            try:
                text = self._call(system, user)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps({"model": self.model, "text": text}))
                return text
            except urllib.error.HTTPError as e:
                detail = e.read().decode(errors="replace")[:300]
                if e.code in (429, 500, 502, 503, 504) and attempt < self.max_retries - 1:
                    time.sleep(delay)
                    delay *= 2
                    continue
                raise ProviderError(f"{self.name} HTTP {e.code}: {detail}") from e
            except (urllib.error.URLError, TimeoutError) as e:
                if attempt < self.max_retries - 1:
                    time.sleep(delay)
                    delay *= 2
                    continue
                raise ProviderError(f"{self.name} unreachable: {e}") from e
        raise ProviderError(f"{self.name}: retries exhausted")


class Gemini(Provider):
    name = "gemini"

    def _call(self, system, user):
        key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
        if not key:
            raise ProviderError("Set GEMINI_API_KEY (or GOOGLE_API_KEY)")
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent"
        body = {"systemInstruction": {"parts": [{"text": system}]},
                "contents": [{"role": "user", "parts": [{"text": user}]}],
                "generationConfig": {"temperature": self.temperature, "responseMimeType": "application/json"}}
        data = _post(url, body, {"x-goog-api-key": key})
        try:
            return "".join(p.get("text", "") for p in data["candidates"][0]["content"]["parts"])
        except (KeyError, IndexError) as e:
            raise ProviderError(f"gemini: unexpected response {str(data)[:300]}") from e


class Anthropic(Provider):
    name = "anthropic"

    def _call(self, system, user):
        key = os.getenv("ANTHROPIC_API_KEY")
        if not key:
            raise ProviderError("Set ANTHROPIC_API_KEY")
        body = {"model": self.model, "max_tokens": 700, "temperature": self.temperature, "system": system,
                "messages": [{"role": "user", "content": user}]}
        data = _post("https://api.anthropic.com/v1/messages", body,
                     {"x-api-key": key, "anthropic-version": "2023-06-01"})
        return "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text")


class OpenAICompatible(Provider):
    name = "openai"
    base_env, key_env, default_base = "OPENAI_BASE_URL", "OPENAI_API_KEY", "https://api.openai.com/v1"

    def _call(self, system, user):
        base = os.getenv(self.base_env, self.default_base).rstrip("/")
        headers = {}
        key = os.getenv(self.key_env)
        if key:
            headers["Authorization"] = f"Bearer {key}"
        body = {"model": self.model, "temperature": self.temperature,
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
                "response_format": {"type": "json_object"}}
        data = _post(f"{base}/chat/completions", body, headers, timeout=300)
        return data["choices"][0]["message"]["content"]


class Ollama(OpenAICompatible):
    name = "ollama"
    base_env, key_env = "OLLAMA_BASE_URL", "OLLAMA_API_KEY"
    default_base = "http://localhost:11434/v1"

    def _call(self, system, user):
        base = os.getenv(self.base_env, "http://localhost:11434").rstrip("/")
        if not base.endswith("/v1"):
            os.environ[self.base_env] = base + "/v1"
        return super()._call(system, user)


PROVIDERS = {p.name: p for p in (Gemini, Anthropic, OpenAICompatible, Ollama)}


def get_provider(name: str, **kw) -> Provider:
    if name not in PROVIDERS:
        raise ProviderError(f"Unknown provider {name!r}. Choose from {sorted(PROVIDERS)}")
    return PROVIDERS[name](**kw)


def parse_json(text: str) -> dict:
    """Parse a JSON object from model output, tolerating code fences and surrounding prose."""
    t = text.strip()
    if t.startswith("```"):
        t = t.strip("`")
        t = t[t.find("{"):] if "{" in t else t
    start, end = t.find("{"), t.rfind("}")
    if start == -1 or end == -1:
        raise ValueError("no JSON object in model output")
    return json.loads(t[start:end + 1])
