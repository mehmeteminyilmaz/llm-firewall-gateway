import asyncio
import json
from fastapi.testclient import TestClient
from app.main import app

def test_api_endpoint():
    print("\n=== FASTAPI ENDPOINT ENTEGRASYON TESTİ ===")
    client = TestClient(app)

    # 1. Health check
    health_resp = client.get("/health")
    print(f"Health Check: {health_resp.status_code} -> {health_resp.json()}")
    assert health_resp.status_code == 200

    # 2. Secure chat POST isteği
    payload = {
        "prompt": "Müşterinin T.C. Kimlik numarası 12345678901 ve e-postası test@sirket.com. API anahtarımız sk-live9876543210abcdef1234567890abcdef. Bu kullanıcıya hoş geldin mesajı üret.",
        "model": "gpt-3.5-turbo"
    }
    
    print("\n[POST /v1/chat/secure İstek Gönderiliyor]")
    resp = client.post("/v1/chat/secure", json=payload)
    print(f"Status Code: {resp.status_code}")
    assert resp.status_code == 200, f"Hata: {resp.text}"

    data = resp.json()
    print("\n[Sunucu Yanıtı (JSON)]:")
    print(json.dumps(data, indent=2, ensure_ascii=False))

    # Doğrulamalar
    assert "12345678901" not in data["masked_prompt_sent_to_llm"], "T.C. Kimlik maskelenmemiş!"
    assert "sk-live9876543210abcdef1234567890abcdef" not in data["masked_prompt_sent_to_llm"], "API key maskelenmemiş!"
    assert "test@sirket.com" not in data["masked_prompt_sent_to_llm"], "Email maskelenmemiş!"
    assert "12345678901" in data["response"], "Unmasking yapılamamış!"
    assert data["latency_ms"] > 0, "Latency hesaplanamadı!"

    print("\n[+] API Entegrasyon Testi Eksiksiz BAŞARILI!")

if __name__ == "__main__":
    test_api_endpoint()
