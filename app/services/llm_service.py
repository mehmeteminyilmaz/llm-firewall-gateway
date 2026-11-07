import asyncio
import json
import os
import httpx
from typing import Any, AsyncIterator, Dict, List, Optional


# 1K (1.000) Token başına tahmini USD maliyet tablosu (Kurumsal LLMOps Maliyet İzleme)
MODEL_PRICING_PER_1K: Dict[str, Dict[str, float]] = {
    "gpt-3.5-turbo": {"prompt": 0.0005, "completion": 0.0015},
    "gpt-4o": {"prompt": 0.0025, "completion": 0.0100},
    "gpt-4o-mini": {"prompt": 0.00015, "completion": 0.0006},
    "claude-3-5-sonnet": {"prompt": 0.0030, "completion": 0.0150},
    "llama-3-70b": {"prompt": 0.0006, "completion": 0.0008},
}


class UpstreamLLMError(Exception):
    """Hedef LLM servisine ulaşılamadığında veya hata döndüğünde fırlatılır."""


class LLMService:
    """
    Hedef LLM (OpenAI, Groq, Ollama, vLLM vb.) ile asenkron iletişim sağlar.
    Gerçek API anahtarı yoksa güvenli fallback simülasyon yanıtı, token ve maliyet metrikleri üretir.
    """

    def __init__(self):
        api_key = os.getenv("LLM_API_KEY") or os.getenv("OPENAI_API_KEY", "")
        placeholder = ("dummy" in api_key.lower() or "your_" in api_key.lower() or not api_key.strip())
        self.api_key = "" if placeholder else api_key
        self.api_url = os.getenv("LLM_API_URL") or os.getenv("UPSTREAM_LLM_URL", "https://api.openai.com/v1/chat/completions")
        self.default_model = os.getenv("LLM_MODEL") or os.getenv("DEFAULT_MODEL", "gpt-3.5-turbo")
        self.timeout = float(os.getenv("UPSTREAM_TIMEOUT_SEC", "30"))

    @property
    def mode(self) -> str:
        return "live" if self.api_key else "simulated"

    @staticmethod
    def calculate_cost(prompt_tokens: int, completion_tokens: int, model: str = "gpt-3.5-turbo") -> float:
        """Model bazlı tahmini USD maliyetini hesaplar."""
        rates = MODEL_PRICING_PER_1K.get(model, MODEL_PRICING_PER_1K["gpt-3.5-turbo"])
        cost = (prompt_tokens / 1000.0) * rates["prompt"] + (completion_tokens / 1000.0) * rates["completion"]
        return round(cost, 6)

    async def stream_response(
        self,
        model: Optional[str] = None,
        messages: Optional[List[Dict[str, str]]] = None,
        temperature: float = 0.3,
    ) -> AsyncIterator[Dict[str, Any]]:
        """
        Yanıtı parça parça üretir. Olaylar:
          {"type": "delta", "text": str}
          {"type": "usage", "prompt_tokens": int, "completion_tokens": int}
        Hedef LLM'e ulaşılamazsa UpstreamLLMError fırlatır (ilk parça alınmadan önce).
        """
        selected_model = model or self.default_model
        messages = messages or []

        if not self.api_key:
            last_user = next((m["content"] for m in reversed(messages) if m["role"] == "user"), "")
            content = f"Sistem güvenli yanıtı: Talebiniz işlendi. Referans: {last_user}"
            # Küçük parçalar yer tutucuların parça sınırlarına denk gelmesini de simüle eder
            for i in range(0, len(content), 8):
                yield {"type": "delta", "text": content[i:i + 8]}
                await asyncio.sleep(0)
            yield {
                "type": "usage",
                "prompt_tokens": sum(len(m["content"].split()) for m in messages),
                "completion_tokens": 12,
            }
            return

        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        payload = {
            "model": selected_model,
            "messages": messages,
            "temperature": temperature,
            "stream": True,
            "stream_options": {"include_usage": True},
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                async with client.stream("POST", self.api_url, json=payload, headers=headers) as resp:
                    if resp.status_code != 200:
                        raise UpstreamLLMError(f"Upstream LLM returned HTTP {resp.status_code}")
                    async for line in resp.aiter_lines():
                        if not line.startswith("data:"):
                            continue
                        data = line[5:].strip()
                        if data == "[DONE]":
                            break
                        try:
                            obj = json.loads(data)
                        except json.JSONDecodeError:
                            continue
                        usage = obj.get("usage")
                        if usage:
                            yield {
                                "type": "usage",
                                "prompt_tokens": usage.get("prompt_tokens", 0),
                                "completion_tokens": usage.get("completion_tokens", 0),
                            }
                        for choice in obj.get("choices", []):
                            text = (choice.get("delta") or {}).get("content")
                            if text:
                                yield {"type": "delta", "text": text}
        except httpx.HTTPError as exc:
            raise UpstreamLLMError(f"Upstream LLM unreachable: {exc.__class__.__name__}") from exc

    async def generate_response(
        self,
        prompt: Optional[str] = None,
        model: Optional[str] = None,
        messages: Optional[List[Dict[str, str]]] = None,
        temperature: float = 0.3,
    ) -> Dict[str, Any]:
        """
        Maskelenmiş prompt'u (veya maskelenmiş çok turlu mesaj geçmişini) hedef LLM API'sine iletir.
        """
        selected_model = model or self.default_model
        if messages is None:
            messages = [{"role": "user", "content": prompt or ""}]

        # Gerçek API anahtarı tanımlanmamışsa fallback simülasyonu çalışır
        if not self.api_key:
            last_user = next((m["content"] for m in reversed(messages) if m["role"] == "user"), "")
            prompt_tokens = sum(len(m["content"].split()) for m in messages)
            completion_tokens = 12
            return {
                "content": f"Sistem güvenli yanıtı: Talebiniz işlendi. Referans: {last_user}",
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": prompt_tokens + completion_tokens,
                "estimated_cost_usd": self.calculate_cost(prompt_tokens, completion_tokens, selected_model),
                "model": selected_model,
                "mode": "simulated",
            }

        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        payload = {"model": selected_model, "messages": messages, "temperature": temperature}

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(self.api_url, json=payload, headers=headers)
        except httpx.HTTPError as exc:
            raise UpstreamLLMError(f"Upstream LLM unreachable: {exc.__class__.__name__}") from exc

        if resp.status_code != 200:
            # Upstream gövdesi istemciye aynen iletilmez (anahtar/iç bilgi sızıntısını önlemek için)
            raise UpstreamLLMError(f"Upstream LLM returned HTTP {resp.status_code}")

        data = resp.json()
        content = data["choices"][0]["message"]["content"]
        usage = data.get("usage", {})
        p_tokens = usage.get("prompt_tokens", 0)
        c_tokens = usage.get("completion_tokens", 0)

        return {
            "content": content,
            "prompt_tokens": p_tokens,
            "completion_tokens": c_tokens,
            "total_tokens": usage.get("total_tokens", p_tokens + c_tokens),
            "estimated_cost_usd": self.calculate_cost(p_tokens, c_tokens, selected_model),
            "model": selected_model,
            "mode": "live",
        }
