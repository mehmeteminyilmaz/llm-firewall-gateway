import os
import httpx
from typing import Dict, Any, Optional


class LLMService:
    """
    Hedef LLM (OpenAI, Groq, Ollama, vLLM vb.) ile asenkron iletişim sağlar.
    Gerçek API anahtarı yoksa güvenli fallback simülasyon yanıtı ve token metrikleri üretir.
    """

    def __init__(self):
        # OpenAI, Groq veya yerel Ollama API adresleri
        # Eğer gerçek bir API anahtarı yoksa, fallback olarak akıllı simülasyon yanıtı üretir
        api_key = os.getenv("LLM_API_KEY") or os.getenv("OPENAI_API_KEY", "")
        # Dummy anahtarları simülasyon moduna yönlendir
        self.api_key = "" if ("dummy" in api_key.lower() or not api_key.strip()) else api_key
        self.api_url = os.getenv("LLM_API_URL") or os.getenv("UPSTREAM_LLM_URL", "https://api.openai.com/v1/chat/completions")
        self.default_model = os.getenv("LLM_MODEL") or os.getenv("DEFAULT_MODEL", "gpt-3.5-turbo")

    async def generate_response(self, prompt: str, model: Optional[str] = None) -> Dict[str, Any]:
        """
        Maskelenmiş prompt'u hedef LLM API'sine asenkron olarak iletir.
        """
        selected_model = model or self.default_model

        # Eğer gerçek API anahtarı tanımlanmamışsa fallback simülasyonu çalışır
        if not self.api_key:
            prompt_tokens = len(prompt.split())
            completion_tokens = 12
            return {
                "content": f"Sistem güvenli yanıtı: Talebiniz işlendi. Referans: {prompt}",
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": prompt_tokens + completion_tokens,
                "mode": "simulated"
            }

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

        payload = {
            "model": selected_model,
            "messages": [
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.3
        }

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(self.api_url, json=payload, headers=headers)
            if resp.status_code != 200:
                raise Exception(f"LLM API Hatası ({resp.status_code}): {resp.text}")

            data = resp.json()
            content = data["choices"][0]["message"]["content"]
            usage = data.get("usage", {})

            return {
                "content": content,
                "prompt_tokens": usage.get("prompt_tokens", 0),
                "completion_tokens": usage.get("completion_tokens", 0),
                "total_tokens": usage.get("total_tokens", 0),
                "mode": "live"
            }
