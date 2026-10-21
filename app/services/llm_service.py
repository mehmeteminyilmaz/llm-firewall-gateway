import httpx
from typing import Optional, Dict, Any
from app.core.config import settings


class LLMService:
    """Hedef LLM servisi (OpenAI, Ollama, yerel vLLM vb.) ile asenkron iletişim sağlar."""

    def __init__(self, api_key: Optional[str] = None, upstream_url: Optional[str] = None):
        self.api_key = api_key or settings.OPENAI_API_KEY
        self.upstream_url = upstream_url or settings.UPSTREAM_LLM_URL

    async def generate_response(self, prompt: str, model: str = "gpt-3.5-turbo", simulate: bool = True) -> str:
        """
        Maskelenmiş promptu asenkron olarak upstream LLM'e iletir.
        Faz 1 aşamasında varsayılan olarak simülasyon modu aktiftir.
        """
        if simulate or not self.api_key or "dummy" in self.api_key:
            # Simüle edilmiş güvenli LLM yanıtı
            return f"Model yanıtı: İşlem talebiniz alındı. İlgili veri referansı: {prompt}"

        # Gerçek LLM çağrısı (Faz 2 ve Faz 3 için hazır asenkron httpx istemcisi)
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": model,
            "messages": [
                {"role": "user", "content": prompt}
            ]
        }
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(self.upstream_url, json=payload, headers=headers)
            response.raise_for_status()
            data = response.json()
            return data["choices"][0]["message"]["content"]
