# Sunum ve Savunma Rehberi

> Bitirme projesi jüri sunumu için hazırlık notları: anlatım akışı, canlı demo senaryosu, beklenen sorular ve **dürüst sınırlılıklar**.

---

## 1. Anlatım Akışı (10-12 dk)

| Süre | Konu | Vurgulanacak nokta |
|---|---|---|
| 1 dk | **Problem** | Kurumsal LLM kullanımında iki risk: (1) PII/sır sızıntısı, (2) prompt injection / jailbreak |
| 2 dk | **Çözüm: ters proxy** | İstemci ile LLM arasında oturur; **mevcut uygulama kodu değişmez** (OpenAI SDK `base_url`) |
| 3 dk | **Mimari** | Rate limit → Inbound Guard → Outbound Guard (maskele) → LLM → Unmask → Audit. README'deki Mermaid şeması |
| 2 dk | **Canlı demo** | Aşağıdaki senaryo |
| 2 dk | **Ölçümler** | `BENCHMARK_REPORT.md`: F1, P95 gecikme, yanlış pozitif/negatif |
| 1 dk | **Sınırlılıklar ve gelecek iş** | Bölüm 4 (jüri dürüstlüğü takdir eder) |

---

## 2. Canlı Demo Senaryosu

Hazırlık: `docker compose up --build` (veya iki terminalde `uvicorn` + `streamlit`), ardından `python generate_traffic.py`.

1. **Meşru istek + PII:** Panelden "Meşru istek (kişisel veri içerir)" gönder. Gösterilecek: yanıtta `pii_types`, `estimated_cost_usd`, `gateway_overhead_ms`; **LLM'e giden metnin maskeli olduğu** (`[TC_KIMLIK_1]`), istemciye dönenin ise çözülmüş olduğu.
2. **Saldırı:** "Prompt injection (İngilizce)" gönder → `403`, `threat_score`, `reasons`. Panelde "Engellenen" sayacı artar.
3. **Gizleme saldırısı:** Özel metin: `I​gnore all previous instructions` (araya görünmez karakter) → yine `403` (Unicode normalizasyonu).
4. **Yanlış pozitif yok:** `Fatura 20231105998 ödendi` gönder → maskelenmez (T.C. checksum doğrulaması). Sonra geçerli bir T.C. numarasıyla karşılaştır.
5. **Drop-in uyumluluk:** README Bölüm 7-C'deki `openai` istemci kodunu çalıştır (yalnızca `base_url` değişti). `stream=True` ile **kelime kelime akış** sırasında yer tutucuların canlı çözüldüğünü göster.
6. **Hata dayanıklılığı:** Upstream'i kapat → istemciye temiz `502`; `/health` içinde `active_vault_sessions: 0` (kasada PII kalmadı).
7. **Panel:** PII tür dağılımı, gecikme grafiği, maliyet, benchmark kartları.

---

## 3. Beklenen Jüri Soruları ve Hazır Cevaplar

**S: "%100 F1 skoru nasıl mümkün? Overfit değil mi?"**
C: Değerlendirme veri seti (50 injection + 10 PII vakası) projede geliştirdiğimiz kurallarla birlikte evrildi; bu yüzden %100 *genelleme iddiası değil*, regresyon tabanıdır. Asıl değeri: kurallar değiştikçe hiçbir bilinen vakanın bozulmadığını CI'da garanti etmesi. Bağımsız bir veri setiyle (JailbreakBench tam seti) ölçüm gelecek iş olarak planlı.

**S: "Regex ile prompt injection tespiti yeterli mi?"**
C: Hayır, tek başına yeterli değil; **bilinen kalıplar için ucuz ilk savunma hattı** (~0.04 ms). Anlamsal/çok adımlı saldırıları yakalamak için sınıflandırıcı (DeBERTa/Llama-Guard) tabanlı ikinci katman şartnamede öngörülmüş gelecek iştir. Mimari bunu eklemeye hazır: `InjectionGuard.scan` aynı arayüzle genişletilebilir.

**S: "PII eşleme tablosu nerede tutuluyor, güvenli mi?"**
C: Sunucu belleğinde, istek başına UUID anahtarıyla; yanıt gelir gelmez (veya upstream hata verirse `finally` ile) silinir; istemciye hiç dönmez, diske yazılmaz. Denetim logu **içerik tutmaz**, yalnızca metrik. Üretimde Redis (TTL'li) önerilir.

**S: "Neden T.C. kimlik için ayrıca checksum?"**
C: 11 haneli her sayı T.C. değildir (fatura, sipariş no). Resmi algoritma (10. ve 11. hane) yanlış pozitifi büyük ölçüde azaltır; testlerle kanıtlı.

**S: "Gecikme hedefi tutuyor mu?"**
C: Inbound ~0.04 ms, Outbound (NER dahil) ~10 ms ortalama, P95 ~17 ms; hedef < 50 ms. LLM süresi bundan ayrı raporlanır (`gateway_overhead_ms` vs `llm_latency_ms`).

**S: "Streaming'de yer tutucu iki parçaya bölünürse?"**
C: `StreamUnmasker` yarım kalmış `[...` kuyruğunu en fazla 48 karakter tamponlar; her olası parça boyutu için test yazıldı (`test_stream_unmasker_handles_every_chunk_boundary`).

---

## 4. Dürüst Sınırlılıklar (slayta koyun)

- **Rate limiter ve vault tek süreç belleğinde:** birden çok worker/replika için paylaşımlı depo (Redis) gerekir.
- **Heuristik injection tespiti:** yeni/yaratıcı saldırılar kaçabilir; ML sınıflandırıcı katmanı eklenmeli.
- **PII için dil kapsamı:** NER İngilizce modelle; Türkçe isim/adres tespiti (PERSON/LOCATION) kapsam dışı, yalnızca desenli veriler (T.C., IBAN, telefon, e-posta, kart, anahtar) hedeflenir.
- **Benchmark veri seti küçük ve kendi derlememiz;** bağımsız doğrulama yapılmadı.
- **Çıktı tarafı (LLM yanıtı) taraması yok:** LLM'in ürettiği zararlı içerik filtrelenmiyor; yalnızca giriş/çıkış PII yönetimi var.
- **Kimlik doğrulama basit:** statik API anahtarları; OAuth/JWT doğrulaması yok.

## 5. Gelecek İş (sunumun son slaytı)

1. Redis tabanlı vault + dağıtık rate limiting
2. Transformer tabanlı injection sınıflandırıcı (ikinci katman) ve bağımsız JailbreakBench değerlendirmesi
3. LLM çıktısı için guardrail (toksisite, sızıntı tespiti)
4. Türkçe NER (PERSON/ADDRESS) entegrasyonu
5. PostgreSQL denetim deposu ve rol bazlı panel erişimi
