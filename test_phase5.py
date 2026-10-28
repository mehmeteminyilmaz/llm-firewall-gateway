from fastapi.testclient import TestClient
from app.main import app
from app.core.vault import vault_store
from app.guards.pii_guard import PIIGuard


def run_phase5_tests():
    print("=== FAZ 5 TESTİ: OPENAI DROP-IN PROXY, MALİYET, PII TÜR DAĞILIMI VE RATE LIMIT ===")
    vault_store.reset_rate_limits()
    client = TestClient(app)

    # 1. OpenAI SDK Uyumlu /v1/chat/completions Endpoint Testi
    openai_payload = {
        "model": "gpt-4o",
        "messages": [
            {"role": "system", "content": "Sen kurumsal bir asistansın."},
            {
                "role": "user",
                "content": "Müşterimiz Mehmet Bey (TC: 10000000146, Tel: +905321112233, E-posta: mehmet@kurum.com) için özet oluştur.",
            },
        ],
    }

    resp = client.post("/v1/chat/completions", json=openai_payload)
    assert resp.status_code == 200, f"Hata: {resp.text}"
    data = resp.json()

    assert data["object"] == "chat.completion"
    assert "choices" in data and len(data["choices"]) == 1
    content = data["choices"][0]["message"]["content"]
    assert "10000000146" in content and "mehmet@kurum.com" in content

    meta = data["guardrail_metadata"]
    assert meta["pii_detected_count"] == 3
    assert meta["pii_types"]["TC_KIMLIK"] == 1
    assert meta["pii_types"]["PHONE_NUMBER"] == 1
    assert meta["pii_types"]["EMAIL_ADDRESS"] == 1
    assert meta["estimated_cost_usd"] > 0.0
    assert resp.headers.get("X-Guardrail-Status") == "SUCCESS"
    assert resp.headers.get("X-Guardrail-PII-Masked") == "3"
    print("[+] 1. OpenAI Uyumlu (/v1/chat/completions), PII Tür Dağılımı ve USD Maliyet Testi BAŞARILI!")

    # 2. Resmi T.C. Kimlik Algoritmik Checksum Doğrulaması
    assert PIIGuard.is_valid_tc_checksum("10000000146") is True
    assert PIIGuard.is_valid_tc_checksum("12345678901") is False
    print("[+] 2. T.C. Kimlik Algoritmik Checksum Doğrulaması BAŞARILI!")

    # 3. Sliding-Window Rate Limiting (HTTP 429) Testi
    vault_store.reset_rate_limits()
    orig_limit = vault_store.rate_limit_requests
    vault_store.rate_limit_requests = 3
    try:
        for _ in range(3):
            r = client.post("/v1/chat/secure", json={"prompt": "Merhaba güvenli test"})
            assert r.status_code == 200
        r_blocked = client.post("/v1/chat/secure", json={"prompt": "Limit aşımı testi"})
        assert r_blocked.status_code == 429, f"Beklenen 429, alınan {r_blocked.status_code}"
        print("[+] 3. Sliding-Window Rate Limiting (HTTP 429 Too Many Requests) Testi BAŞARILI!")
    finally:
        vault_store.rate_limit_requests = orig_limit
        vault_store.reset_rate_limits()

    print("\n=== TÜM FAZ 5 KURUMSAL TESTLERİ EKSİKSİZ GEÇTİ ===")


if __name__ == "__main__":
    run_phase5_tests()
