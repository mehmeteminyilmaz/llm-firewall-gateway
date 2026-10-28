import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.core.vault import vault_store


def test_phase3_flow():
    print("\n=== FAZ 3 TESTİ: ASENKRON LLM, VAULT CACHE VE TOKEN METRİKLERİ ===")
    client = TestClient(app)

    # 1. Meşru İstek (PII içeren kurumsal prompt)
    payload = {
        "prompt": "Müşterimiz Ayşe Hanım'ın T.C. Kimlik No 98765432150 ve iletişim adresi ayse@kurum.com'dur. Kendisine abonelik yenileme bildirimi hazırla.",
        "model": "gpt-3.5-turbo"
    }

    resp = client.post("/v1/chat/secure", json=payload)
    print(f"Status: {resp.status_code}")
    assert resp.status_code == 200, f"Hata: {resp.text}"

    data = resp.json()
    print("\n[Sunucu Yanıtı (JSON)]:")
    import json
    print(json.dumps(data, indent=2, ensure_ascii=False))

    # Doğrulamalar:
    # A) Status SUCCESS olmalı
    assert data["status"] == "SUCCESS"

    # B) vault_mappings istemciye ASLA sızdırılmamalı!
    assert "vault_mappings" not in data, "GÜVENLİK AÇIĞI: vault_mappings istemciye sızdırıldı!"

    # C) PII tespit adedi > 0 olmalı
    assert data["pii_detected_count"] >= 1, "HATA: PII tespit edilemedi!"

    # D) Token bilgileri dönmeli
    assert "tokens" in data
    assert data["tokens"]["prompt_tokens"] > 0
    assert data["tokens"]["completion_tokens"] > 0
    assert data["tokens"]["total_tokens"] > 0

    # E) Gecikme metrikleri ayrışmış olmalı
    assert "gateway_overhead_ms" in data
    assert "llm_latency_ms" in data
    assert "total_latency_ms" in data

    # F) Yanıt unmask edilmiş olmalı (Ayşe Hanım'ın TC ve e-postası geri açılmış olmalı)
    assert "98765432150" in data["response"], "HATA: T.C. Kimlik unmask edilemedi!"
    assert "ayse@kurum.com" in data["response"], "HATA: E-posta unmask edilemedi!"

    # G) Zero-Leakage: Vault temizlenmiş olmalı
    assert vault_store.size() == 0, f"HATA: Vault temizlenmedi, kalan oturum: {vault_store.size()}"

    print("\n[+] Zero-Leakage Doğrulaması: Bellek kasası derhal silindi (Kalan Oturum = 0)")
    print("[+] Token Metrikleri: Başarıyla hesaplandı")
    print("[+] Gecikme Ayrımı: Gateway Overhead vs LLM Latency ayrıştırıldı")
    print("[+] Unmasking Doğrulaması: Tamamlandı")
    print("\n=== TÜM FAZ 3 TESTLERİ EKSİKSİZ GEÇTİ ===")


if __name__ == "__main__":
    test_phase3_flow()
