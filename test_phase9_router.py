"""
Faz 9: Akıllı Çoklu Sağlayıcı Yönlendiricisi & Otomatik Yedekleme (Smart Multi-Provider Router & Failover) Testleri.

Doğrulanan özellikler:
1. Model adına göre sağlayıcı sınıflandırması (Ollama Local GPU, Groq Cloud, OpenAI Cloud, Anthropic Cloud).
2. Bulut API anahtarı yokken aktif yerel GPU sağlayıcısına (Ollama) otomatik yönlendirme (Static Failover).
3. Birincil sağlayıcı (ör. bulut veya yerel birincil model) HTTP 500/503 hata döndürdüğünde yedek sağlayıcıya
   otomatik geçiş (Dynamic Runtime Failover) ve yanıtın başarıyla dönmesi.
4. GET /v1/providers uç noktasının sağlayıcı yönlendirme tablosunu döndürmesi.
"""
from fastapi.testclient import TestClient

from app.api import proxy
from app.main import app
from app.services.llm_service import LLMService, UpstreamLLMError

client = TestClient(app)


def test_provider_classification_by_model_name():
    assert LLMService.classify_provider("qwen2.5:1.5b") == "ollama-local"
    assert LLMService.classify_provider("llama3.2:1b") == "ollama-local"
    assert LLMService.classify_provider("gemma2:2b") == "ollama-local"
    assert LLMService.classify_provider("llama-3.3-70b-versatile") == "groq-cloud"
    assert LLMService.classify_provider("llama-3-70b") == "groq-cloud"
    assert LLMService.classify_provider("gpt-4o") == "openai-cloud"
    assert LLMService.classify_provider("gpt-4o-mini") == "openai-cloud"
    assert LLMService.classify_provider("claude-3-5-sonnet") == "anthropic-cloud"


def test_static_failover_routes_cloud_model_to_local_ollama_when_cloud_key_missing(monkeypatch):
    """
    Sadece yerel Ollama yapılandırılmışken (OPENAI_API_KEY=ollama), kullanıcı panelden 'gpt-4o'
    veya 'llama-3.3-70b-versatile' seçerse HTTP 404/502 almak yerine otomatik olarak yerel
    GPU yedek modeline (qwen2.5:1.5b) yönlendirilmeli.
    """
    monkeypatch.setenv("OPENAI_API_KEY", "ollama")
    monkeypatch.setenv("UPSTREAM_LLM_URL", "http://127.0.0.1:11434/v1/chat/completions")
    monkeypatch.setenv("FALLBACK_MODEL", "qwen2.5:1.5b")
    monkeypatch.setenv("GROQ_API_KEY", "")

    svc = LLMService()
    assert svc.mode == "live"

    # 1. Yerel model doğrudan ollama-local'e gider
    r_local = svc.resolve_route("llama3.2:1b")
    assert r_local["provider"] == "ollama-local"
    assert r_local["resolved_model"] == "llama3.2:1b"
    assert r_local["failover_triggered"] is False

    # 2. Bulut modeli (gpt-4o) anahtarı olmadığı için yerel GPU yedek modeline (qwen2.5:1.5b) düşer
    r_cloud = svc.resolve_route("gpt-4o")
    assert r_cloud["provider"] == "ollama-local-fallback"
    assert r_cloud["requested_model"] == "gpt-4o"
    assert r_cloud["resolved_model"] == "qwen2.5:1.5b"
    assert r_cloud["failover_triggered"] is True


def test_dynamic_runtime_failover_when_primary_provider_fails(monkeypatch):
    """
    Hem Groq bulut anahtarı hem de yerel Ollama tanımlıyken, Groq HTTP 503 döndürürse
    LLMService otomatik olarak yerel Ollama yedek rotasına geçmeli (Graceful Failover).
    """
    monkeypatch.setenv("OPENAI_API_KEY", "ollama")
    monkeypatch.setenv("UPSTREAM_LLM_URL", "http://127.0.0.1:11434/v1/chat/completions")
    monkeypatch.setenv("GROQ_API_KEY", "gsk_live_test_key_123456")
    monkeypatch.setenv("FALLBACK_MODEL", "qwen2.5:1.5b")

    svc = LLMService()
    calls = []

    async def mock_post(api_url, api_key, model_name, messages, temperature):
        calls.append((api_url, model_name))
        if "groq.com" in api_url:
            raise UpstreamLLMError("Upstream LLM returned HTTP 503")
        return {
            "choices": [{"message": {"content": "Yerel yedek GPU modelinden güvenli yanıt."}}],
            "usage": {"prompt_tokens": 12, "completion_tokens": 8, "total_tokens": 20},
        }

    monkeypatch.setattr(svc, "_post_completion", mock_post)
    monkeypatch.setattr(proxy, "llm_service", svc)

    resp = client.post(
        "/v1/chat/secure",
        json={"prompt": "Müşteri TC 10000000146 için bakiye özeti hazırla.", "model": "llama-3.3-70b-versatile"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "SUCCESS"
    assert data["failover_triggered"] is True
    assert data["provider"] == "ollama-local-fallback"
    assert data["resolved_model"] == "qwen2.5:1.5b"
    assert len(calls) == 2
    assert "groq.com" in calls[0][0]
    assert "11434" in calls[1][0]


def test_providers_endpoint_returns_routing_table():
    resp = client.get("/v1/providers")
    assert resp.status_code == 200
    body = resp.json()
    assert "providers" in body
    assert "allow_cloud_fallback" in body
    names = [p["provider"] for p in body["providers"]]
    assert "ollama-local" in names
    assert "groq-cloud" in names
    assert "openai-cloud" in names


def test_failover_cost_uses_resolved_model_pricing(monkeypatch):
    """Failover sırasında maliyet, istenen modele (gpt-4o) göre değil gerçekte çalışan modele (qwen2.5:1.5b) göre hesaplanmalı."""
    monkeypatch.setenv("OPENAI_API_KEY", "ollama")
    monkeypatch.setenv("UPSTREAM_LLM_URL", "http://127.0.0.1:11434/v1/chat/completions")
    monkeypatch.setenv("FALLBACK_MODEL", "qwen2.5:1.5b")
    monkeypatch.setenv("GROQ_API_KEY", "")

    svc = LLMService()

    async def mock_post(api_url, api_key, model_name, messages, temperature):
        return {
            "choices": [{"message": {"content": "Tamamlandı."}}],
            "usage": {"prompt_tokens": 1000, "completion_tokens": 1000, "total_tokens": 2000},
        }

    monkeypatch.setattr(svc, "_post_completion", mock_post)
    monkeypatch.setattr(proxy, "llm_service", svc)

    resp = client.post("/v1/chat/secure", json={"prompt": "Kısa bir merhaba de.", "model": "gpt-4o"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["resolved_model"] == "qwen2.5:1.5b"
    # qwen2.5:1.5b fiyatı: 0.0001 + 0.0002 = 0.0003 (gpt-4o olsa 0.0125 olurdu)
    assert data["estimated_cost_usd"] == 0.0003


def test_on_premise_model_does_not_failover_to_cloud_unless_opted_in(monkeypatch):
    """
    Veri yerleşimi (data residency) koruması: Kullanıcı yerel GPU modelini (qwen2.5:1.5b) seçtiğinde
    ALLOW_CLOUD_FALLBACK=false iken buluta (groq-cloud) sessizce geçiş yapmamalı (HTTP 502).
    Yalnızca ALLOW_CLOUD_FALLBACK=true ile açık onay verilince buluta geçmeli.
    """
    monkeypatch.setenv("OPENAI_API_KEY", "ollama")
    monkeypatch.setenv("UPSTREAM_LLM_URL", "http://127.0.0.1:11434/v1/chat/completions")
    monkeypatch.setenv("GROQ_API_KEY", "gsk_live_test_key_123456")
    monkeypatch.setenv("ALLOW_CLOUD_FALLBACK", "false")

    svc_strict = LLMService()
    assert svc_strict.allow_cloud_fallback is False

    async def fail_ollama(api_url, api_key, model_name, messages, temperature):
        if "11434" in api_url:
            raise UpstreamLLMError("Ollama offline")
        return {
            "choices": [{"message": {"content": "Bulut yanıtı."}}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
        }

    monkeypatch.setattr(svc_strict, "_post_completion", fail_ollama)
    monkeypatch.setattr(proxy, "llm_service", svc_strict)

    r_blocked = client.post("/v1/chat/secure", json={"prompt": "Merhaba", "model": "qwen2.5:1.5b"})
    assert r_blocked.status_code == 502

    # Şimdi açık onay (ALLOW_CLOUD_FALLBACK=true) ile test et
    monkeypatch.setenv("ALLOW_CLOUD_FALLBACK", "true")
    svc_optin = LLMService()
    monkeypatch.setattr(svc_optin, "_post_completion", fail_ollama)
    monkeypatch.setattr(proxy, "llm_service", svc_optin)

    r_ok = client.post("/v1/chat/secure", json={"prompt": "Merhaba", "model": "qwen2.5:1.5b"})
    assert r_ok.status_code == 200
    assert r_ok.json()["failover_triggered"] is True
    assert r_ok.json()["provider"] == "groq-cloud-fallback"
