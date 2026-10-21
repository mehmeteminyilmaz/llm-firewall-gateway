# BİTİRME PROJESİ ŞARTNAMESİ VE DETAYLI MİMARİ

**Proje Adı:** Enterprise LLM Guardrail & Gateway: Kurumsal Büyük Dil Modelleri İçin Yüksek Performanslı Güvenlik Proxy'si ve LLMOps İzleme Sistemi

---

## 1. Projenin Konusu ve Amacı (Problem Statement)
Günümüzde şirketler ve kurumlar verimliliği artırmak amacıyla Büyük Dil Modellerini (LLM - OpenAI, Anthropic, yerel LLM'ler vb.) iş süreçlerine entegre etmektedir. Ancak bu durum iki büyük güvenlik ve yönetim riskini beraberinde getirmektedir:
1. **Dışarıya Hassas Veri Sızıntısı (Data Leakage):** Çalışanların müşteri verilerini, T.C. Kimlik No, kredi kartı bilgilerini veya şirket kaynak kodlarını istemeden (prompt içinde) dış servislerle paylaşması.
2. **İçeriye Yönelik Güvenlik Tehditleri (Prompt Injection & Jailbreak):** Saldırganların veya kötü niyetli kullanıcıların özel komutlarla LLM'i manipüle ederek sistem talimatlarını aşması veya zararlı içerik ürettirmesi.

**Projenin Amacı:** İstemci (çalışan/uygulama) ile hedef LLM arasında bir **Reverse Proxy (Ara Katman)** gibi çalışarak:
- Dışarı giden istemlerdeki (prompt) hassas verileri anlık anonimleştiren (maskeleyen),
- İçeri giden taleplerdeki güvenlik tehditlerini milisaniyeler seviyesinde engelleyen,
- Tüm bu trafiği LLMOps metrikleriyle raporlayan bir kurumsal güvenlik duvarı geliştirmektir.

---

## 2. Sistem Kapsamı ve Bileşenleri (4 Ana Modül)

### 1. Outbound Guard (Hassas Veri Maskeleme / Anonymization Modülü)
- Kullanıcının LLM'e gönderdiği metin içerisindeki T.C. Kimlik No, Kredi Kartı, API Key/Token, E-posta ve Telefon Numaraları tespit edilir.
- **İki Yönlü Maskeleme (Reversible Anonymization):** Veri LLM'e gitmeden önce yer tutucularla (ör. `[TC_KIMLIK_1]`, `[KREDİ_KARTI_1]`) maskelenir. LLM'den yanıt döndüğünde maskelenmiş veriler orijinal haliyle değiştirilerek kullanıcıya sunulur. Böylece LLM, gerçek kişisel veriyi hiç görmemiş olur.

### 2. Inbound Guard (Prompt Injection & Jailbreak Engelleyici Modülü)
- Kullanıcıdan gelen prompt'un LLM'i manipüle etmeye çalışıp çalışmadığı tespit edilir.
- Gelen istek için $0.0 - 1.0$ arasında bir **Tehdit Skoru (Threat Score)** üretilir.
- Belirlenen eşik değerin ($0.70$) üstündeki istekler LLM'e ulaşmadan **403 Forbidden** yanıtı ile engellenir ve loglanır.

### 3. LLMOps & Performans Analiz Modülü
- **Gecikme Süresi (Latency Overhead):** Güvenlik duvarının isteğe eklediği gecikme süresi ($ms$ cinsinden) anlık hesaplanır.
- **Maliyet ve Token Takibi:** Kullanılan toplam Prompt ve Completion token sayıları izlenir, tahmini maliyet çıkarılır.

### 4. SOC & Güvenlik Yönetim Paneli (Dashboard)
- Engellenen Prompt Injection denemeleri,
- Sızdırılması engellenen hassas veri türleri,
- Sistem gecikme grafikleri,
- Kullanıcı bazlı kullanım istatistiklerinin görselleştirildiği web tabanlı yönetim paneli.

---

## 3. Teknik Yaklaşım ve Mimari (Nasıl Yapılacak?)
- **Mimari Yapı:** Yüksek eşzamanlı istek (concurrent requests) desteği sağlamak için **Asenkron Reverse Proxy** mimarisi (FastAPI, Uvicorn, HTTPX).
- **Hassas Veri Tespiti (PII Detection):**
  - Statik ve desenli veriler için Regex & Kural Motorları (Luhn Algoritması vb.).
  - İsim, adres gibi dinamik veriler için NER (Named Entity Recognition) modelleri (Microsoft Presidio ve Spacy modelleri).
- **Tehdit Tespiti (Prompt Injection Engine):**
  - İstek sürelerini uzatmamak için hafif sınıflandırıcılar (Fine-tuned DeBERTa / RoBERTa / DistilBERT) veya açık kaynaklı güvenlik modelleri (Llama-Guard / ShieldGemma).
- **Veri Yönetimi & Önbellek (Vault / Cache):**
  - Maskelenen verilerin anlık eşleşmesini güvenli tutmak ve rate-limiting uygulamak için bellek içi veritabanı (**Redis**).
  - Güvenlik ihlal logları ve istatistikler ilişkisel veritabanında (**PostgreSQL**) saklanacaktır.

---

## 4. Akademik Değer ve Ölçümleme (Evaluation Planı)
Projenin başarısı ve akademik geçerliliği aşağıdaki objektif metriklerle test edilip raporlanacaktır:
1. **Performans / Gecikme (Latency Overhead Testi):** Güvenlik duvarının sistem gecikmesine etkisi test edilecek; hedef, ek gecikmeyi minimumda ($<50\text{ ms}$) tutmaktır.
2. **Güvenlik Başarımı (F1-Score, Precision, Recall):** Açık kaynaklı Prompt Injection/Jailbreak veri setleri (JailbreakBench, InfiBench) üzerinde modelin güvenlik yakalama başarısı ölçülecektir.
3. **PII Maskeleme Doğruluğu:** Oluşturulacak sentetik test verileri üzerinden hassas verilerin kaçırma yapılmadan maskelenme oranı analiz edilecektir.
