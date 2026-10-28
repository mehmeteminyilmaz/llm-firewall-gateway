import os
import httpx
from typing import Dict, Any, Optional


# 1K (1.000) Token başına tahmini USD maliyet tablosu (Kurumsal LLMOps Maliyet İzleme)
MODEL_PRICING_PER_1K: Dict[str, Dict[str, float]] = {
    "gpt-3.5-turbo": {"prompt": 0.0005, "completion": 0.0015},
    "gpt-4o": {"prompt": 0.0025, "completion": 0.0100},
    "gpt-4o-mini": {"prompt": 0.00015, "completion": 0.0006},
    "claude-3-5-sonnet": {"prompt": 0.0030, "completion": 0.0150},
    "llama-3-70b": {"prompt": 0.0006, "completion": 0.0008},
}


class LLMService:
    """
    Hedef LLM (OpenAI, Groq, Ollama, vLLM vb.) ile asenkron iletişim sağlar.
    Gerçek API anahtarı yoksa güvenli fallback simülasyon yanıtı, token ve maliyet metrikleri üretir.
    """

    def __init__(self):
        api_key = os.getenv("LLM_API_KEY") or os.getenv("OPENAI_API_KEY", "")
        self.api_key = "" if ("dummy" in api_key.lower() or not api_key.strip()) else api_key
        self.api_url = os.getenv("LLM_API_URL") or os.getenv("UPSTREAM_LLM_URL", "https://api.openai.com/v1/chat/completions")
        self.default_model = os.getenv("LLM_MODEL") or os.getenv("DEFAULT_MODEL", "gpt-3.5-turbo")

    @staticmethod
    def calculate_cost(prompt_tokens: int, completion_tokens: int, model: str = "gpt-3.5-turbo") -> float:
        """Model bazlı tahmini USD maliyetini hesaplar."""
        rates = MODEL_PRICING_PER_1K.get(model, MODEL_PRICING_PER_1K["gpt-3.5-turbo"])
        cost = (prompt_tokens / 1000.0) * rates["prompt"] + (completion_tokens / 1000.0) * rates["completion"]
        return round(cost, 6)

    async def generate_response(self, prompt: str, model: Optional[str] = None) -> Dict[str, Any]:
        """
        Maskelenmiş prompt'u hedef LLM API'sine asenkron olarak iletir.
        """
        selected_model = model or self.default_model

        # Eğer gerçek API anahtarı tanımlanmamışsa fallback simülasyonu çalışır
        if not self.api_key:
            prompt_tokens = len(prompt.split())
            completion_tokens = 12
            total_tokens = prompt_tokens + completion_tokens
            estimated_cost_usd = self.calculate_cost(prompt_tokens, completion_tokens, selected_model)
            return {
                "content": f"Sistem güvenli yanıtı: Talebiniz işlendi. Referans: {prompt}",
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": total_tokens,
                "estimated_cost_usd": estimated_cost_usd,
                "model": selected_model,
                "mode": "simulated",
            }

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        payload = {
            "model": selected_model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.3,
        }

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(self.api_url, json=payload, headers=headers)
            if resp.status_code != 200:
                raise Exception(f"LLM API Hatası ({resp.status_code}): {resp.text}")

            data = resp.json()
            content = data["choices"][0]["message"]["content"]
            usage = data.get("usage", {})
            p_tokens = usage.get("prompt_tokens", 0)
            c_tokens = usage.get("completion_tokens", 0)
            t_tokens = usage.get("total_tokens", p_tokens + c_tokens)

            return {
                "content": content,
                "prompt_tokens": p_tokens,
                "completion_tokens": c_tokens,
                "total_tokens": t_tokens,
                "estimated_cost_usd": self.calculate_cost(p_tokens, c_tokens, selected_model),
                "model": selected_model,
                "mode": "live",
            }
