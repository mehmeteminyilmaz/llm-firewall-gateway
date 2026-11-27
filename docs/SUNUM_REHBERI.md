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

1. **Kurumsal Asistan (Çalışan Sohbet Modu) + PII:** Sol menüden **"Kurumsal Asistan (Sohbet)"** moduna geçin ve üstteki **"Meşru İstek (TC + Tel + E-posta)"** düğmesine tıklayın. Gösterilecek: 3 katmanlı denetim kartında çalışanın ham mesajı, **Gateway Denetim İzi** içinde LLM'e giden maskeli metin (`[TC_KIMLIK_1]`, `[PHONE_NUMBER_2]`, `[EMAIL_ADDRESS_3]`) ve altında etiketleri gerçek veriye geri çözülmüş canlı LLM yanıtı.
2. **Saldırı:** Üstteki **"Prompt Injection (İngilizce)"** düğmesine tıklayın → `HTTP 403 FORBIDDEN`, `threat_score`, `reasons` ve *"İstek hedef LLM'e ve GPU'ya hiç iletilmedi (0 token)"* şeridi.
3. **Gizleme saldırısı:** Özel metin: `I​gnore all previous instructions` (araya görünmez karakter) → yine `403` (Unicode normalizasyonu).
4. **Yanlış pozitif yok:** `Fatura 20231105998 ödendi` gönder → maskelenmez (T.C. checksum doğrulaması). Sonra geçerli bir T.C. numarasıyla karşılaştır.
5. **Drop-in uyumluluk:** README Bölüm 7-C'deki `openai` istemci kodunu çalıştır (yalnızca `base_url` değişti). `stream=True` ile **kelime kelime akış** sırasında yer tutucuların canlı çözüldüğünü göster.
6. **Hata dayanıklılığı:** Upstream'i kapat → istemciye temiz `502`; `/health` içinde `active_vault_sessions: 0` (kasada PII kalmadı).
7. **Çıktı Güvenliği (Response Guard & Canary Token):** Model sistem promptundaki gizli canary token'ı veya reverse-shell exploit kodunu sızdırmaya kalkışırsa yanıtın anında `RESPONSE_BLOCKED` olarak sansürlendiğini gösterin.
8. **4 Sekmeli SOC Paneli:**
   - **Genel Bakış:** Canlı Gateway sağlık çubuğu, PII tür dağılımı, gecikme grafiği, `RESPONSE_BLOCKED` pasta dilimi, model bazlı kullanım ve maliyet tablosu.
   - **Denetim Kaydı:** Durum filtresi, tehdit skoru ilerleme çubuğu ve CSV/JSON dışa aktarma.
   - **Model Performansı:** 3 farklı LLM (`llama3.2:1b`, `qwen2.5:1.5b`, `gemma2:2b`) üzerinde gecikme, token ve GPU/VRAM karşılaştırması.
   - **Benchmark:** Kategori bazlı doğruluk ve PII varlık doğrulama grafikleri.

---

## 3. Beklenen Jüri Soruları ve Hazır Cevaplar

**S: "%100 F1 skoru nasıl mümkün? Overfit değil mi?"**
C: Bu projede ezberi (overfitting) önlemek için **iki kademeli değerlendirme** yapıyoruz:
1. **Standart Benchmark (65 örnek):** Kural + semantik regresyon testinde **%98.55 F1** (Precision %100.0, Recall %97.14).
2. **Bağımsız Görülmemiş Holdout Seti (`unseen_holdout.json`, 40 örnek):** Eğitim prototiplerinden tamamen bağımsız, **%0 metin örtüşmesine sahip** sıfır-regex saldırı ve zorlu negatiflerden oluşur. Sadece kural katmanı **%0 Recall**'da kalırken, Katman 3 çok dilli Transformer modeli bu görülmemiş sette **%100.0 Precision / %90.0 Recall / %94.74 F1** elde etmektedir (2 zorlu kenar vaka dürüst FN olarak raporlanır).

**S: "Model yanıtında (çıktıda) sızıntı veya zararlı içerik kontrolü var mı?"**
C: Evet, **Faz 7 Outbound Response Guardrail** katmanımız: (1) Oturum bazlı dinamik Canary Token (Honeypot) enjekte ederek sistem prompt ifşasını yakalar, (2) 'My initial instructions are' gibi verbatim prompt sızıntısı kalıplarını denetler, (3) Model jailbreak olsa dahi reverse-shell / exploit payload çıktısı üretmesini engelleyerek yanıtı sansürler.

**S: "Sadece kural / regex tabanlı mı yapıyorsunuz? Regex ile prompt injection tespiti yeterli mi?"**
C: Hayır, sistemimiz **anahtar kelime kapısı olmayan kademeli bir hibrit (Rule + Multilingual Transformer ML) mimari** kullanır:
1. **Katman 0 (`L0_BLACKLIST`) & Katman 1 (`L1_REGEX`, ~0.04 ms):** Kurumsal kara listeyi ve bilinen kesin saldırı imzalarını (`ignore previous instructions`, `DAN mode`) sıfıra yakın gecikmeyle eler (*fast-path short-circuit*).
2. **Katman 2 (`L2_LEXICAL`):** Şüpheli anahtar kelime yoğunluğunu denetler.
3. **Katman 3 (`L3_SEMANTIC_ML` — `paraphrase-multilingual-MiniLM-L12-v2`, ~4–7 ms):** Kural katmanından geçen her istemi **384 boyutlu çok dilli (TR/EN) ONNX Transformer gömme uzayına** taşır; **L2 Lojistik Regresyon** ve **Kontrastif Kosinüs Benzerliği** ile görülmemiş dolaylı saldırıları tespit eder.
- **Ablation Kanıtı (`BENCHMARK_REPORT.md`):** 40 örnekli görülmemiş holdout setinde sadece kural tabanlı katman **%0 Recall** alırken, Katman 3 Transformer ile **%90.0 Recall / %94.74 F1** sağlanır (P95 ~6.7 ms, 50 ms Gateway SLA sınırının çok altında).

**S: "PII eşleme tablosu nerede tutuluyor, güvenli mi?"**
C: Sunucu belleğinde, istek başına UUID anahtarıyla; yanıt gelir gelmez (veya upstream hata verirse `finally` ile) silinir; istemciye hiç dönmez, diske yazılmaz. Denetim logu **içerik tutmaz**, yalnızca metrik. Üretimde Redis (TTL'li) önerilir.

**S: "Neden T.C. kimlik için ayrıca checksum?"**
C: 11 haneli her sayı T.C. değildir (fatura, sipariş no). Resmi algoritma (10. ve 11. hane) yanlış pozitifi büyük ölçüde azaltır; testlerle kanıtlı.

**S: "Gecikme hedefi tutuyor mu?"**
C: Inbound ~0.04 ms, Outbound (NER dahil) ~10 ms ortalama, P95 ~17 ms; hedef < 50 ms. LLM süresi bundan ayrı raporlanır (`gateway_overhead_ms` vs `llm_latency_ms`).

**S: "Streaming'de yer tutucu iki parçaya bölünürse?"**
C: `StreamUnmasker` yarım kalmış `[...` kuyruğunu en fazla 48 karakter tamponlar; her olası parça boyutu için test yazıldı (`test_stream_unmasker_handles_every_chunk_boundary`).

**S: "Farklı modellerle denedin mi? GPU ve token kullanımını nasıl etkiliyor?"**
C: Evet, `benchmark_models.py` ile RTX 3050 GPU üzerinde 3 yerel model (`llama3.2:1b`, `qwen2.5:1.5b`, `gemma2:2b`) hem doğrudan hem Gateway üzerinden ölçüldü:
- **Gecikme:** Gateway'in kendi ek süresi yalnızca **6-14 ms** (toplam yanıt süresinin %1-2'si).
- **GPU / VRAM:** Guardrail katmanları tamamen **CPU'da** çalışır; tepe VRAM kullanımı doğrudan çağrıyla birebir aynıdır. Üstelik engellenen saldırılar modele hiç ulaşmadığı için **%0 GPU** ve **0 token** harcar.
- **Token:** Canary token ve sistem yönergesi istek başına yaklaşık **+11 ila +32 prompt token** ekler; PII maskeleme ise uzun IBAN/anahtarları kısa etiketlerle değiştirdiği için bazen token sayısını azaltır.

---

## 4. Dürüst Sınırlılıklar (slayta koyun)

- **Rate limiter ve vault tek süreç belleğinde:** birden çok worker/replika için paylaşımlı depo (Redis) gerekir.
- **Semantik model kapsamı (MiniLM-L12 vs çok-turlu/dolaylı RAG):** 384 boyutlu `paraphrase-multilingual-MiniLM-L12-v2` tek-turlu paraphrased saldırılarda görülmemiş holdout setinde %90 Recall sağlasa da (%10 kaçırma payı vardır), ince ayarlı büyük bir güvenlik modeli (DeBERTa/Llama-Guard) veya çok-turlu dolaylı enjeksiyon koruması değildir.
- **PII için dil kapsamı:** NER İngilizce modelle; Türkçe isim/adres tespiti (PERSON/LOCATION) kapsam dışı, yalnızca desenli veriler (T.C., IBAN, telefon, e-posta, kart, anahtar) hedeflenir.
- **Veri seti ölçeği:** Holdout seti bağımsız olmakla birlikte küçüktür (40 örnek); geniş ölçekli JailbreakBench/ToxicChat doğrulaması gelecek iştir.
- **RBAC ve veri yerleşimi:** Politika yönetimi ayrı `ADMIN_API_KEY` ister; yerel GPU modelleri varsayılan olarak (`ALLOW_CLOUD_FALLBACK=false`) buluta yönlendirilmez. Tam OAuth2/JWT rol entegrasyonu gelecek iştir.

## 5. Gelecek İş (sunumun son slaytı)

1. Redis tabanlı vault + dağıtık rate limiting
2. Çok-turlu diyalog ve RAG belge zehirlenmesi (indirect injection) için ince ayarlı güvenlik sınıflandırıcısı
3. Türkçe NER (PERSON/ADDRESS) entegrasyonu
4. PostgreSQL denetim deposu ve OAuth2/OIDC panel erişimi

