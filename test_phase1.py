import asyncio
import json
from app.guards.pii_guard import PIIGuard


def test_pii_mask_and_unmask():
    print("=== 1. PII GUARD TESTİ BAŞLATILIYOR ===")
    guard = PIIGuard()

    sample_prompt = (
        "Müşterinin T.C. Kimlik numarası 12345678950 ve e-postası test@sirket.com. "
        "API anahtarımız sk-live9876543210abcdef1234567890abcdef. "
        "Bu kullanıcıya hoş geldin mesajı üret."
    )

    print(f"\n[Gelen Ham Prompt]:\n{sample_prompt}")

    masked_prompt, vault = guard.mask(sample_prompt)

    print(f"\n[Maskelenmiş Prompt (LLM'e Gidecek)]:\n{masked_prompt}")
    print(f"\n[Kasa / Vault Eşlemeleri]:\n{json.dumps(vault, indent=2, ensure_ascii=False)}")

    # Doğrulamalar
    assert "12345678950" not in masked_prompt, "HATA: T.C. Kimlik maskelenemedi!"
    assert "test@sirket.com" not in masked_prompt, "HATA: E-posta maskelenemedi!"
    assert "sk-live9876543210abcdef1234567890abcdef" not in masked_prompt, "HATA: API Anahtarı maskelenemedi!"

    print("\n[+] Maskeleme doğrulamaları BAŞARILI!")

    # Simüle edilmiş LLM yanıtı
    simulated_llm_response = f"Model yanıtı: İşlem talebiniz alındı. İlgili veri referansı: {masked_prompt}"
    restored_text = guard.unmask(simulated_llm_response, vault)

    print(f"\n[LLM Yanıtı (Maskeli)]:\n{simulated_llm_response}")
    print(f"\n[Geri Açılmış Son Yanıt (Unmasked)]:\n{restored_text}")

    assert "12345678950" in restored_text, "HATA: T.C. Kimlik geri açılamadı!"
    assert "test@sirket.com" in restored_text, "HATA: E-posta geri açılamadı!"
    assert "sk-live9876543210abcdef1234567890abcdef" in restored_text, "HATA: API Anahtarı geri açılamadı!"

    print("\n[+] Tersine eşleme (Unmasking) doğrulamaları BAŞARILI!")
    print("\n=== TÜM FAZ 1 TESTLERİ GEÇTİ ===")


if __name__ == "__main__":
    test_pii_mask_and_unmask()
