# Akademik Benchmark ve Ablation Değerlendirme Raporu (Faz 8 - Hibrit Semantik Guard)

> **Oluşturulma Tarihi:** `2026-11-22 19:13:12`  
> **Veri Seti:** `Enterprise LLM Guardrail Benchmark Suite (v1.1.0)`

---

## 1. Yönetici Özeti ve SLA Doğrulaması

| Değerlendirme Boyutu | Ölçülen Değer | Akademik / Kurumsal Hedef | Durum |
|---|---|---|---|
| **Inbound Guard F1-Skoru** (Hibrit L1 Regex + L3 Semantik ML) | **%100.0** | $> \%95.0$ | BAŞARILI |
| **Inbound Guard Kesinlik / Duyarlılık** (Precision / Recall) | **%100.0 / %100.0** | $> \%95.0$ | BAŞARILI |
| **Outbound Guard PII Maskeleme F1-Skoru** | **%100.0** | $\%100.0$ | BAŞARILI |
| **Reversible Unmasking & Zero-Leakage Başarımı** | **%100.0 / %100.0** | $\%100.0$ | BAŞARILI |
| **Inbound Guard Gecikmesi (Ort. / P95)** | **0.2058 ms / 0.8079 ms** | $< 5\text{ ms}$ | BAŞARILI |
| **Outbound PII + Vault Gecikmesi (Ort. / P95)** | **10.06 ms / 16.19 ms** | $< 50\text{ ms}$ (SLA) | BAŞARILI |

---

## 2. Ablation Analizi: Sadece Kural Tabanlı (L1/L2) vs Hibrit Semantik ML (L1+L2+L3)

Kelimeleri değiştirilmiş (paraphrased / zero-regex) saldırıların dahil edildiği **65 örnekli** veri setinde kural tabanlı yaklaşım ile 3 katmanlı hibrit semantik mimarinin karşılaştırması:

| Mimari Yapı | TP / FN | Precision | Recall (Duyarlılık) | F1-Score | Ort. Gecikme | P95 Gecikme |
|---|---|---|---|---|---|---|
| **Sadece Kural Tabanlı (L1 Regex + L2 Leksikal)** | `25 / 10` | `%100.0` | `%71.43` | `%83.33` | `0.0375 ms` | `0.051 ms` |
| **Hibrit Mimari (L1 Regex + L2 Leksikal + L3 Semantik ML)** | **`35 / 0`** | **`%100.0`** | **`%100.0`** | **`%100.0`** | **`0.2058 ms`** | **`0.8079 ms`** |

### Katman Bazlı Yakalama Dağılımı (Hibrit Mod)
- **Katman 1 (`L1_REGEX` — Deterministik İmza Motoru):** `24` saldırıyı ~0.04 ms hızında doğrudan yakaladı (Fast-path short-circuit).
- **Katman 2 (`L2_LEXICAL` — Leksikal Yoğunluk):** `1` saldırıyı yakaladı.
- **Katman 3 (`L3_SEMANTIC_ML` — TF-IDF Alt-Kelime Vektör + Kontrastif Kosinüs + Lojistik Regresyon):** Kural katmanını atlatan **`10` semantik / dolaylı saldırıyı** yakalayarak Recall değerini `%71.43` seviyesinden **`%100.0`** seviyesine çıkardı.

---

## 3. Inbound Guard: Prompt Injection & Jailbreak Değerlendirmesi

*JailbreakBench*, *InfiBench / OWASP LLM01* ve *Semantic Zero-Regex Evasion* sınıflandırmalarından derlenen toplam **65 örnek** (35 saldırı, 30 meşru/zorlu negatif kurumsal istem) üzerinde test edilmiştir.

### 3.1. Karışıklık Matrisi (Confusion Matrix) ve Sınıflandırma Metrikleri

| Metrik | Değer | Açıklama |
|---|---|---|
| **True Positive (TP)** | `35` | Doğru şekilde tespit edilip bloklanan (HTTP 403) saldırı istemleri |
| **True Negative (TN)** | `30` | Yanlış alarm üretilmeden onaylanan (HTTP 200) meşru ve teknik istemler |
| **False Positive (FP)** | `0` | Yanlışlıkla engellenen meşru istem sayısı |
| **False Negative (FN)** | `0` | Gözden kaçan saldırı istemi sayısı |
| **Accuracy (Doğruluk)** | **%100.0** | $(TP + TN) / Toplam$ |
| **Precision (Kesinlik)** | **%100.0** | $TP / (TP + FP)$ |
| **Recall (Duyarlılık)** | **%100.0** | $TP / (TP + FN)$ |
| **F1-Score** | **%100.0** | $2 \cdot (Precision \cdot Recall) / (Precision + Recall)$ |

### 3.2. Kategori Bazlı Yakalama Başarımı

| Kategori | Örnek Sayısı | Doğru Karar | Başarı Oranı |
|---|---|---|---|
| Direct Instruction Override | 7 | 7 | **%100.0** |
| Roleplay / Persona Adoption (JailbreakBench) | 6 | 6 | **%100.0** |
| System Prompt Extraction | 5 | 5 | **%100.0** |
| Delimiter & Context Spoofing | 3 | 3 | **%100.0** |
| Obfuscation & Payload Execution (InfiBench) | 2 | 2 | **%100.0** |
| Hypothetical / Malicious Framing (JailbreakBench) | 2 | 2 | **%100.0** |
| Semantic / Paraphrased Evasion (Zero-Regex) | 10 | 10 | **%100.0** |
| Benign - Software Engineering (InfiBench) | 6 | 6 | **%100.0** |
| Benign - Corporate & Finance | 6 | 6 | **%100.0** |
| Benign - Hard Negative (Security & Technical Context) | 12 | 12 | **%100.0** |
| Benign - Data Science & AI | 6 | 6 | **%100.0** |

---

## 4. Outbound Guard: PII Maskeleme ve Zero-Leakage Vault Değerlendirmesi

Kurumsal senaryoları temsil eden **10 sentetik test vakası** ve toplam **19 hassas varlık** üzerinde gerçekleştirilmiştir.

### 4.1. Varlık Türüne Göre Maskeleme Başarımı

| Varlık Türü (Entity) | Beklenen | Tespit Edilen | Doğru Eşleşen (TP) | Duyarlılık (Recall) |
|---|---|---|---|---|
| `TC_KIMLIK` | 5 | 5 | 5 | **%100.0** |
| `EMAIL_ADDRESS` | 7 | 7 | 7 | **%100.0** |
| `API_KEY` | 3 | 3 | 3 | **%100.0** |
| `PHONE_NUMBER` | 2 | 2 | 2 | **%100.0** |
| `TR_IBAN` | 1 | 1 | 1 | **%100.0** |
| `JWT_TOKEN` | 1 | 1 | 1 | **%100.0** |

- **PII Precision:** `%100.0`
- **PII Recall:** `%100.0`
- **PII F1-Score:** `%100.0`
- **Reversible Unmasking Doğruluğu:** `%100.0` (Tüm yer tutucular orijinal metne kayıpsız geri dönüştürüldü)
- **Zero-Leakage Bellek Temizliği:** `%100.0` (Her işlem sonunda `MemoryVault` oturumu derhal imha edildi)

---

## 5. Performans ve Gecikme (Latency Overhead) Analizi

| Katman | Ortalama (Mean) | Medyan (P50) | P95 Gecikme | SLA Hedefi |
|---|---|---|---|---|
| **Inbound Guard (Sadece L1/L2 Kural)** | `0.0375 ms` | `0.0358 ms` | `0.051 ms` | `< 5.0 ms` |
| **Inbound Guard (Hibrit L1 Regex + L3 Semantik ML)** | `0.2058 ms` | `0.0514 ms` | `0.8079 ms` | `< 5.0 ms` |
| **Outbound Guard (Presidio NER + Regex + Vault)** | `10.06 ms` | `7.7 ms` | `16.19 ms` | `< 50.0 ms` |
