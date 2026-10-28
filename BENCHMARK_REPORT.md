# Akademik Benchmark ve Performans Değerlendirme Raporu (Faz 4b)

> **Oluşturulma Tarihi:** `2026-10-29 00:29:13`  
> **Veri Seti:** `Enterprise LLM Guardrail Benchmark Suite (v1.0.0)`

---

## 1. Yönetici Özeti ve SLA Doğrulaması

| Değerlendirme Boyutu | Ölçülen Değer | Akademik / Kurumsal Hedef | Durum |
|---|---|---|---|
| **Inbound Guard F1-Skoru** (Prompt Injection & Jailbreak) | **%100.0** | $> \%95.0$ | BAŞARILI |
| **Inbound Guard Kesinlik / Duyarlılık** (Precision / Recall) | **%100.0 / %100.0** | $> \%95.0$ | BAŞARILI |
| **Outbound Guard PII Maskeleme F1-Skoru** | **%100.0** | $\%100.0$ | BAŞARILI |
| **Reversible Unmasking & Zero-Leakage Başarımı** | **%100.0 / %100.0** | $\%100.0$ | BAŞARILI |
| **Inbound Guard Gecikmesi (Ort. / P95)** | **0.0416 ms / 0.0463 ms** | $< 5\text{ ms}$ | BAŞARILI |
| **Outbound PII + Vault Gecikmesi (Ort. / P95)** | **11.34 ms / 16.8 ms** | $< 50\text{ ms}$ (SLA) | BAŞARILI |

---

## 2. Inbound Guard: Prompt Injection & Jailbreak Değerlendirmesi

*JailbreakBench* ve *InfiBench / OWASP LLM01* sınıflandırmalarından derlenen toplam **50 örnek** (25 saldırı, 25 meşru/zorlu negatif kurumsal istem) üzerinde test edilmiştir.

### 2.1. Karışıklık Matrisi (Confusion Matrix) ve Sınıflandırma Metrikleri

| Metrik | Değer | Açıklama |
|---|---|---|
| **True Positive (TP)** | `25` | Doğru şekilde tespit edilip bloklanan (HTTP 403) saldırı istemleri |
| **True Negative (TN)** | `25` | Yanlış alarm üretilmeden onaylanan (HTTP 200) meşru ve teknik istemler |
| **False Positive (FP)** | `0` | Yanlışlıkla engellenen meşru istem sayısı |
| **False Negative (FN)** | `0` | Gözden kaçan saldırı istemi sayısı |
| **Accuracy (Doğruluk)** | **%100.0** | $(TP + TN) / Toplam$ |
| **Precision (Kesinlik)** | **%100.0** | $TP / (TP + FP)$ |
| **Recall (Duyarlılık)** | **%100.0** | $TP / (TP + FN)$ |
| **F1-Score** | **%100.0** | $2 \cdot (Precision \cdot Recall) / (Precision + Recall)$ |

### 2.2. Kategori Bazlı Yakalama Başarımı

| Kategori | Örnek Sayısı | Doğru Karar | Başarı Oranı |
|---|---|---|---|
| Direct Instruction Override | 7 | 7 | **%100.0** |
| Roleplay / Persona Adoption (JailbreakBench) | 6 | 6 | **%100.0** |
| System Prompt Extraction | 5 | 5 | **%100.0** |
| Delimiter & Context Spoofing | 3 | 3 | **%100.0** |
| Obfuscation & Payload Execution (InfiBench) | 2 | 2 | **%100.0** |
| Hypothetical / Malicious Framing (JailbreakBench) | 2 | 2 | **%100.0** |
| Benign - Software Engineering (InfiBench) | 5 | 5 | **%100.0** |
| Benign - Corporate & Finance | 5 | 5 | **%100.0** |
| Benign - Hard Negative (Security & Technical Context) | 10 | 10 | **%100.0** |
| Benign - Data Science & AI | 5 | 5 | **%100.0** |

---

## 3. Outbound Guard: PII Maskeleme ve Zero-Leakage Vault Değerlendirmesi

Kurumsal senaryoları temsil eden **8 sentetik test vakası** ve toplam **16 hassas varlık** üzerinde gerçekleştirilmiştir.

### 3.1. Varlık Türüne Göre Maskeleme Başarımı

| Varlık Türü (Entity) | Beklenen | Tespit Edilen | Doğru Eşleşen (TP) | Duyarlılık (Recall) |
|---|---|---|---|---|
| `EMAIL_ADDRESS` | 6 | 6 | 6 | **%100.0** |
| `TC_KIMLIK` | 5 | 5 | 5 | **%100.0** |
| `API_KEY` | 3 | 3 | 3 | **%100.0** |
| `PHONE_NUMBER` | 2 | 2 | 2 | **%100.0** |

- **PII Precision:** `%100.0`
- **PII Recall:** `%100.0`
- **PII F1-Score:** `%100.0`
- **Reversible Unmasking Doğruluğu:** `%100.0` (Tüm yer tutucular orijinal metne kayıpsız geri dönüştürüldü)
- **Zero-Leakage Bellek Temizliği:** `%100.0` (Her işlem sonunda `MemoryVault` oturumu derhal imha edildi)

---

## 4. Performans ve Gecikme (Latency Overhead) Analizi

| Katman | Ortalama (Mean) | Medyan (P50) | P95 Gecikme | SLA Hedefi |
|---|---|---|---|---|
| **Inbound Guard (Regex + Semantik Yoğunluk)** | `0.0416 ms` | `0.0342 ms` | `0.0463 ms` | `< 5.0 ms` |
| **Outbound Guard (Presidio NER + Regex + Vault)** | `11.34 ms` | `8.99 ms` | `16.8 ms` | `< 50.0 ms` |
