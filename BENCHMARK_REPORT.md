# Akademik Benchmark, Holdout Genelleme ve Ablation Raporu

> **Oluşturulma Tarihi:** `2026-11-28 01:39:59`  
> **Birincil Veri Seti:** `Enterprise LLM Guardrail Benchmark Suite (v1.1.0)`  
> **Holdout Veri Seti:** `Enterprise LLM Guardrail Unseen Out-of-Distribution Holdout Suite (v1.0.0)`  
> **Semantik L3 Motoru:** `sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2` (384-dim ONNX Transformer, anahtar kelime kapısı yok)

---

## 1. İki Kademeli Yönetici Özeti ve SLA Doğrulaması

| Değerlendirme Boyutu | Ölçülen Değer | Akademik / Kurumsal Hedef | Durum |
|---|---|---|---|
| **Standart Inbound Guard F1-Skoru** (65 Örnek: L1+L2+L3 MiniLM-L12) | **%98.55** (`P %100.0 / R %97.14`) | $\ge \%92.0$ | BAŞARILI |
| **Bağımsız Holdout F1-Skoru** (40 Görülmemiş Örnek, **%0 Sızıntı**) | **%94.74** (`P %100.0 / R %90.0`) | $\ge \%80.0$ | BAŞARILI |
| **Outbound Guard PII Maskeleme F1-Skoru** (19 Kurumsal Varlık) | **%100.0** | $\%100.0$ | BAŞARILI |
| **Reversible Unmasking & Zero-Leakage Başarımı** | **%100.0 / %100.0** | $\%100.0$ | BAŞARILI |
| **Inbound Guard Gecikmesi (Ort. / P95)** | **3.5882 ms / 6.4385 ms** | $< 35\text{ ms}$ (CPU Transformer) | BAŞARILI |
| **Outbound PII + Vault Gecikmesi (Ort. / P95)** | **9.27 ms / 14.87 ms** | $< 50\text{ ms}$ (SLA) | BAŞARILI |

### Eğitim / Test Veri Sızıntısı Denetimi (Zero-Leakage Verification)
- **`dataset.json` (65 örnek):** Birebir eşleşme = `0`, Maks. 3-gram Jaccard = `0.2994` (`< 0.85`)
- **`unseen_holdout.json` (40 örnek):** Birebir eşleşme = `0`, Maks. 3-gram Jaccard = `0.3228` (`< 0.85`)

---

## 2. Ablation Analizi: Sadece Kural (L1/L2) vs Hibrit Transformer (L1+L2+L3 MiniLM-L12)

| Veri Seti & Mimari Yapı | TP / TN / FP / FN | Precision | Recall | F1-Score | Ort. / P95 Gecikme |
|---|---|---|---|---|---|
| **Standart (65 Örnek) — Sadece Kural (L1/L2)** | `25 / 30 / 0 / 10` | `%100.0` | `%71.43` | `%83.33` | `0.0358 / 0.0484 ms` |
| **Standart (65 Örnek) — Hibrit MiniLM-L12 (L1+L2+L3)** | **`34 / 30 / 0 / 1`** | **`%100.0`** | **`%97.14`** | **`%98.55`** | **`3.5882 / 6.4385 ms`** |
| **Görülmemiş Holdout (40 Örnek) — Sadece Kural (L1/L2)** | `0 / 20 / 0 / 20` | `%0.0` | `%0.0` | `%0.0` | `0.0427 / 0.0567 ms` |
| **Görülmemiş Holdout (40 Örnek) — Hibrit MiniLM-L12 (L1+L2+L3)** | **`18 / 20 / 0 / 2`** | **`%100.0`** | **`%90.0`** | **`%94.74`** | **`5.6749 / 6.6997 ms`** |

> **Metodoloji Notu:** Holdout setindeki sıfır-regex saldırılar kural katmanında `%0.0` Recall değerinde kalırken, eğitim kümesinde hiç yer almayan bu cümlelerde gerçek çok dilli Transformer gömme katmanımız **%90.0 Recall** ve **%100.0 Precision** (%0 yanlış pozitif) elde etmektedir. Kalan `FN=2` hatalar dürüst sınırlılık olarak raporlanmaktadır.

### Katman Bazlı Yakalama Dağılımı (Standart Benchmark)
- **Katman 1 (`L1_REGEX` — Deterministik İmza Motoru):** `24` saldırı
- **Katman 2 (`L2_LEXICAL` — Leksikal Yoğunluk):** `1` saldırı
- **Katman 3 (`L3_SEMANTIC_ML` — `paraphrase-multilingual-MiniLM-L12-v2`):** `9` semantik saldırı

---

## 3. Kategori Bazlı Yakalama Başarımı (`dataset.json`)

| Kategori | Örnek Sayısı | Doğru Karar | Başarı Oranı |
|---|---|---|---|
| Direct Instruction Override | 7 | 7 | **%100.0** |
| Roleplay / Persona Adoption (JailbreakBench) | 6 | 6 | **%100.0** |
| System Prompt Extraction | 5 | 5 | **%100.0** |
| Delimiter & Context Spoofing | 3 | 3 | **%100.0** |
| Obfuscation & Payload Execution (InfiBench) | 2 | 2 | **%100.0** |
| Hypothetical / Malicious Framing (JailbreakBench) | 2 | 2 | **%100.0** |
| Semantic / Paraphrased Evasion (Zero-Regex) | 10 | 9 | **%90.0** |
| Benign - Software Engineering (InfiBench) | 6 | 6 | **%100.0** |
| Benign - Corporate & Finance | 6 | 6 | **%100.0** |
| Benign - Hard Negative (Security & Technical Context) | 12 | 12 | **%100.0** |
| Benign - Data Science & AI | 6 | 6 | **%100.0** |

---

## 4. Outbound Guard: PII Maskeleme ve Zero-Leakage Vault Değerlendirmesi

Kurumsal senaryoları temsil eden **10 sentetik test vakası** ve toplam **19 hassas varlık** üzerinde gerçekleştirilmiştir.

| Varlık Türü (Entity) | Beklenen | Tespit Edilen | Doğru Eşleşen (TP) | Duyarlılık (Recall) |
|---|---|---|---|---|
| `EMAIL_ADDRESS` | 7 | 7 | 7 | **%100.0** |
| `TC_KIMLIK` | 5 | 5 | 5 | **%100.0** |
| `API_KEY` | 3 | 3 | 3 | **%100.0** |
| `PHONE_NUMBER` | 2 | 2 | 2 | **%100.0** |
| `TR_IBAN` | 1 | 1 | 1 | **%100.0** |
| `JWT_TOKEN` | 1 | 1 | 1 | **%100.0** |

- **PII Precision / Recall / F1:** `%100.0` / `%100.0` / `%100.0`
- **Reversible Unmasking & Zero-Leakage:** `%100.0` / `%100.0`
