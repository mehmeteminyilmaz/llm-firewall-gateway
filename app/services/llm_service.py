import asyncio
import json
import os
import httpx
from typing import Any, AsyncIterator, Dict, List, Optional, Tuple


# 1K (1.000) Token başına tahmini USD maliyet tablosu (Kurumsal LLMOps Maliyet İzleme)
MODEL_PRICING_PER_1K: Dict[str, Dict[str, float]] = {
    "gpt-3.5-turbo": {"prompt": 0.0005, "completion": 0.0015},
    "gpt-4o": {"prompt": 0.0025, "completion": 0.0100},
    "gpt-4o-mini": {"prompt": 0.00015, "completion": 0.0006},
    "claude-3-5-sonnet": {"prompt": 0.0030, "completion": 0.0150},
    "llama-3-70b": {"prompt": 0.0006, "completion": 0.0008},
    "llama-3.3-70b-versatile": {"prompt": 0.00059, "completion": 0.00079},
    "openai/gpt-oss-120b": {"prompt": 0.00015, "completion": 0.00060},
    "openai/gpt-oss-20b": {"prompt": 0.00007, "completion": 0.00030},
    "qwen/qwen3.8-27b": {"prompt": 0.00010, "completion": 0.00040},
    "qwen2.5:1.5b": {"prompt": 0.0001, "completion": 0.0002},
    "llama3.2:1b": {"prompt": 0.0001, "completion": 0.0002},
    "gemma2:2b": {"prompt": 0.0001, "completion": 0.0002},
}

DEFAULT_PROVIDER_URLS: Dict[str, str] = {
    "ollama-local": "http://127.0.0.1:11434/v1/chat/completions",
    "groq-cloud": "https://api.groq.com/openai/v1/chat/completions",
    "openai-cloud": "https://api.openai.com/v1/chat/completions",
    "anthropic-cloud": "https://api.anthropic.com/v1/chat/completions",
}


class UpstreamLLMError(Exception):
    """Hedef LLM servisine ulaşılamadığında veya hata döndüğünde fırlatılır."""


def _clean_key(raw: Optional[str]) -> str:
    if not raw:
        return ""
    low = raw.strip().lower()
    if not low or "dummy" in low or "your_" in low:
        return ""
    return raw.strip()


class LLMService:
    """
    Akıllı Çoklu Sağlayıcı Yönlendiricisi (Smart Multi-Provider Router & Failover Engine).

    Özellikler:
    1. Model Adına Göre Otomatik Sağlayıcı Seçimi (Dynamic Model Routing):
       - 'qwen2.5:1.5b', 'llama3.2:1b', 'gemma2:2b' (veya ':' içeren etiketler) -> Yerel GPU (Ollama)
       - 'llama-3.3-70b-versatile', 'llama-3-70b', 'mixtral-*' -> Groq Cloud API
       - 'gpt-4o', 'gpt-4o-mini', 'gpt-3.5-turbo' -> OpenAI Cloud API
       - 'claude-3-5-sonnet', 'claude-*' -> Anthropic Compatible API
    2. Otomatik Yedekleme (High-Availability Graceful Failover):
       - İstenen bulut modelin API anahtarı tanımlı değilse veya birincil sağlayıcı hata/zaman aşımı
         döndürürse, aktif yedek sağlayıcıya (ör. Yerel GPU Ollama modeline) kesintisiz geçiş yapar.
    3. Güvenli Simülasyon Modu (Fallback Simulation):
       - Hiçbir canlı sağlayıcı anahtarı tanımlı değilse deterministik simülasyon yanıtı üretir.
    """

    def __init__(self):
        raw_openai = _clean_key(os.getenv("LLM_API_KEY") or os.getenv("OPENAI_API_KEY", ""))
        self.api_url = os.getenv("LLM_API_URL") or os.getenv("UPSTREAM_LLM_URL", DEFAULT_PROVIDER_URLS["openai-cloud"])
        self.default_model = os.getenv("LLM_MODEL") or os.getenv("DEFAULT_MODEL", "gpt-3.5-turbo")
        self.fallback_model = os.getenv("FALLBACK_MODEL", "qwen2.5:1.5b")
        self.timeout = float(os.getenv("UPSTREAM_TIMEOUT_SEC", "30"))
        self.enable_failover = os.getenv("ENABLE_PROVIDER_FALLBACK", "true").lower() in ("true", "1", "yes")
        # Veri yerleşimi koruması: yerel GPU modeli seçildiğinde açık onay olmadan buluta düşme
        self.allow_cloud_fallback = os.getenv("ALLOW_CLOUD_FALLBACK", "false").lower() in ("true", "1", "yes")

        # Sağlayıcı bazlı anahtar ve uç nokta çözümlemesi
        is_ollama_mode = (raw_openai.lower() == "ollama") or ("11434" in self.api_url)
        is_groq_key = raw_openai.startswith("gsk_")

        self.ollama_key = _clean_key(os.getenv("OLLAMA_API_KEY")) or ("ollama" if is_ollama_mode and raw_openai else "")
        self.ollama_url = os.getenv("OLLAMA_API_URL", self.api_url if "11434" in self.api_url else DEFAULT_PROVIDER_URLS["ollama-local"])

        self.groq_key = _clean_key(os.getenv("GROQ_API_KEY")) or (raw_openai if is_groq_key else "")
        self.groq_url = os.getenv("GROQ_API_URL", DEFAULT_PROVIDER_URLS["groq-cloud"])

        self.openai_key = "" if (is_ollama_mode or is_groq_key) else raw_openai
        self.openai_url = os.getenv("OPENAI_API_URL", DEFAULT_PROVIDER_URLS["openai-cloud"] if "11434" in self.api_url else self.api_url)

        self.anthropic_key = _clean_key(os.getenv("ANTHROPIC_API_KEY"))
        self.anthropic_url = os.getenv("ANTHROPIC_API_URL", DEFAULT_PROVIDER_URLS["anthropic-cloud"])

        # Geriye dönük uyumluluk için anahtar referansı
        self.api_key = raw_openai or self.ollama_key or self.groq_key or self.openai_key or self.anthropic_key

    @property
    def mode(self) -> str:
        return "live" if (self.api_key or self.ollama_key or self.groq_key or self.openai_key or self.anthropic_key) else "simulated"

    @staticmethod
    def classify_provider(model: str) -> str:
        """Model adına göre hedef sağlayıcı ailesini belirler."""
        m = (model or "").strip().lower()
        if m.startswith(("openai/gpt-oss", "qwen/qwen", "allam-", "llama-3", "llama3-", "mixtral", "groq/")):
            return "groq-cloud"
        if ":" in m or m.startswith(("qwen2", "llama3.2", "gemma", "mistral:", "phi", "ollama/")):
            return "ollama-local"
        if m.startswith(("claude", "anthropic/")):
            return "anthropic-cloud"
        return "openai-cloud"

    def _provider_credentials(self, provider: str) -> Tuple[str, str]:
        if provider == "ollama-local":
            return self.ollama_key, self.ollama_url
        if provider == "groq-cloud":
            return self.groq_key, self.groq_url
        if provider == "anthropic-cloud":
            return self.anthropic_key, self.anthropic_url
        return self.openai_key, self.openai_url

    def get_providers_status(self) -> List[Dict[str, Any]]:
        """Tüm desteklenen sağlayıcıların durumunu ve yönlendirme tablosunu döndürür."""
        return [
            {
                "provider": "ollama-local",
                "type": "Local GPU (On-Premise)",
                "endpoint": self.ollama_url,
                "configured": bool(self.ollama_key),
                "models": ["qwen2.5:1.5b", "llama3.2:1b", "gemma2:2b"],
                "fallback_target": self.fallback_model,
            },
            {
                "provider": "groq-cloud",
                "type": "Cloud LPU (High-Speed)",
                "endpoint": self.groq_url,
                "configured": bool(self.groq_key),
                "models": ["openai/gpt-oss-120b", "qwen/qwen3.8-27b", "openai/gpt-oss-20b"],
            },
            {
                "provider": "openai-cloud",
                "type": "Cloud API",
                "endpoint": self.openai_url,
                "configured": bool(self.openai_key),
                "models": ["gpt-4o", "gpt-4o-mini", "gpt-3.5-turbo"],
            },
            {
                "provider": "anthropic-cloud",
                "type": "Cloud API",
                "endpoint": self.anthropic_url,
                "configured": bool(self.anthropic_key),
                "models": ["claude-3-5-sonnet"],
            },
        ]

    def resolve_route(self, requested_model: Optional[str] = None) -> Dict[str, Any]:
        """
        İstenen model için birincil rotayı ve varsa yedek (fallback) rotayı çözümler.
        """
        model = (requested_model or self.default_model).strip()
        target_provider = self.classify_provider(model)

        if self.mode == "simulated":
            return {
                "provider": "simulated",
                "api_url": self.api_url,
                "api_key": "",
                "requested_model": model,
                "resolved_model": model,
                "failover_triggered": False,
                "fallback_route": None,
            }

        key, url = self._provider_credentials(target_provider)

        # Yedek rota adaylarını belirle (Öncelik: Yerel GPU Ollama -> Groq -> OpenAI)
        fallback_candidates = []
        if self.ollama_key:
            fb_model = self.fallback_model if ":" in self.fallback_model else "qwen2.5:1.5b"
            fallback_candidates.append(("ollama-local", self.ollama_key, self.ollama_url, fb_model))
        if self.groq_key:
            fallback_candidates.append(("groq-cloud", self.groq_key, self.groq_url, "openai/gpt-oss-120b"))
        if self.openai_key:
            fallback_candidates.append(("openai-cloud", self.openai_key, self.openai_url, "gpt-4o-mini"))

        # Veri yerleşimi (data residency) kuralı: istemci özellikle yerel GPU (ollama-local)
        # seçtiyse ve ALLOW_CLOUD_FALLBACK kapalıysa bulut sağlayıcılar yedek aday olamaz.
        if target_provider == "ollama-local" and not self.allow_cloud_fallback:
            fallback_candidates = [c for c in fallback_candidates if c[0] == "ollama-local"]

        # 1. Hedef sağlayıcının anahtarı mevcutsa birincil rota olarak kullan
        if key:
            fb_route = None
            if self.enable_failover:
                for fb_prov, fb_key, fb_url, fb_mod in fallback_candidates:
                    if fb_prov != target_provider or fb_mod != model:
                        fb_route = {
                            "provider": f"{fb_prov}-fallback",
                            "api_url": fb_url,
                            "api_key": fb_key,
                            "resolved_model": fb_mod,
                        }
                        break
            return {
                "provider": target_provider,
                "api_url": url,
                "api_key": key,
                "requested_model": model,
                "resolved_model": model,
                "failover_triggered": False,
                "fallback_route": fb_route,
            }

        # 2. Hedef sağlayıcının anahtarı yoksa ancak başka bir canlı sağlayıcı açıksa
        if self.enable_failover and fallback_candidates:
            fb_prov, fb_key, fb_url, fb_mod = fallback_candidates[0]
            return {
                "provider": f"{fb_prov}-fallback",
                "api_url": fb_url,
                "api_key": fb_key,
                "requested_model": model,
                "resolved_model": fb_mod,
                "failover_triggered": True,
                "fallback_route": None,
            }

        # 3. Hedef sağlayıcı için anahtar yok ve uygun yedek rota da yoksa (ör. yerel seçildi ama Ollama kapalı)
        if target_provider == "ollama-local" and not self.allow_cloud_fallback:
            return {
                "provider": "unconfigured",
                "api_url": url,
                "api_key": "",
                "requested_model": model,
                "resolved_model": model,
                "failover_triggered": False,
                "fallback_route": None,
            }

        # Genel api_key / api_url fallback (yalnızca tek genel URL yapılandırmaları için)
        return {
            "provider": target_provider,
            "api_url": self.api_url,
            "api_key": self.api_key,
            "requested_model": model,
            "resolved_model": model,
            "failover_triggered": False,
            "fallback_route": None,
        }

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
        route = self.resolve_route(model)
        selected_model = route["resolved_model"]
        messages = messages or []

        if self.mode == "simulated":
            last_user = next((m["content"] for m in reversed(messages) if m["role"] == "user"), "")
            content = f"Sistem güvenli yanıtı: Talebiniz işlendi. Referans: {last_user}"
            for i in range(0, len(content), 8):
                yield {"type": "delta", "text": content[i:i + 8]}
                await asyncio.sleep(0)
            yield {
                "type": "usage",
                "prompt_tokens": sum(len(m["content"].split()) for m in messages),
                "completion_tokens": 12,
            }
            return

        if not route["api_key"]:
            raise UpstreamLLMError(
                f"Provider for model '{selected_model}' is not configured and cloud fallback is disabled."
            )

        headers = {"Authorization": f"Bearer {route['api_key']}", "Content-Type": "application/json"}
        payload = {
            "model": selected_model,
            "messages": messages,
            "temperature": temperature,
            "stream": True,
            "stream_options": {"include_usage": True},
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                async with client.stream("POST", route["api_url"], json=payload, headers=headers) as resp:
                    if resp.status_code != 200:
                        raise UpstreamLLMError(f"Upstream LLM ({route['provider']}) returned HTTP {resp.status_code}")
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

    async def _post_completion(
        self, api_url: str, api_key: str, model_name: str, messages: List[Dict[str, str]], temperature: float
    ) -> Dict[str, Any]:
        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
        payload = {"model": model_name, "messages": messages, "temperature": temperature}
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(api_url, json=payload, headers=headers)
        except httpx.HTTPError as exc:
            raise UpstreamLLMError(f"Upstream LLM unreachable: {exc.__class__.__name__}") from exc

        if resp.status_code != 200:
            raise UpstreamLLMError(f"Upstream LLM returned HTTP {resp.status_code}")

        return resp.json()

    async def generate_response(
        self,
        prompt: Optional[str] = None,
        model: Optional[str] = None,
        messages: Optional[List[Dict[str, str]]] = None,
        temperature: float = 0.3,
    ) -> Dict[str, Any]:
        """
        Maskelenmiş prompt'u (veya çok turlu mesaj geçmişini) Akıllı Yönlendirici üzerinden
        uygun sağlayıcıya iletir. Birincil sağlayıcı hata verirse yedek rotayı dener.
        """
        route = self.resolve_route(model)
        requested_model = route["requested_model"]
        resolved_model = route["resolved_model"]
        provider = route["provider"]
        failover_triggered = route["failover_triggered"]

        if messages is None:
            messages = [{"role": "user", "content": prompt or ""}]

        # Gerçek API anahtarı tanımlanmamışsa fallback simülasyonu çalışır
        if self.mode == "simulated":
            last_user = next((m["content"] for m in reversed(messages) if m["role"] == "user"), "")
            prompt_tokens = sum(len(m["content"].split()) for m in messages)
            completion_tokens = 12
            return {
                "content": f"Sistem güvenli yanıtı: Talebiniz işlendi. Referans: {last_user}",
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": prompt_tokens + completion_tokens,
                "estimated_cost_usd": self.calculate_cost(prompt_tokens, completion_tokens, requested_model),
                "model": requested_model,
                "resolved_model": requested_model,
                "provider": "simulated",
                "failover_triggered": False,
                "mode": "simulated",
            }

        if not route["api_key"]:
            raise UpstreamLLMError(
                f"Provider for model '{requested_model}' is not configured and cloud fallback is disabled."
            )

        try:
            data = await self._post_completion(
                api_url=route["api_url"],
                api_key=route["api_key"],
                model_name=resolved_model,
                messages=messages,
                temperature=temperature,
            )
        except UpstreamLLMError:
            fb = route.get("fallback_route")
            if not fb:
                raise
            # Birincil sağlayıcı başarısız olduysa yedek sağlayıcıya (Graceful Failover) geç
            data = await self._post_completion(
                api_url=fb["api_url"],
                api_key=fb["api_key"],
                model_name=fb["resolved_model"],
                messages=messages,
                temperature=temperature,
            )
            provider = fb["provider"]
            resolved_model = fb["resolved_model"]
            failover_triggered = True

        content = data["choices"][0]["message"]["content"]
        usage = data.get("usage", {})
        p_tokens = usage.get("prompt_tokens", 0)
        c_tokens = usage.get("completion_tokens", 0)

        return {
            "content": content,
            "prompt_tokens": p_tokens,
            "completion_tokens": c_tokens,
            "total_tokens": usage.get("total_tokens", p_tokens + c_tokens),
            "estimated_cost_usd": self.calculate_cost(p_tokens, c_tokens, resolved_model),
            "model": requested_model,
            "resolved_model": resolved_model,
            "provider": provider,
            "failover_triggered": failover_triggered,
            "mode": "live",
        }
