import re
from typing import Dict, Tuple, List
from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
from presidio_anonymizer import AnonymizerEngine


class PIIGuard:
    """
    Regex ve Presidio tabanlı hibrit PII Maskeleme ve Geri Dönüştürme Motoru.
    Hassas verileri (T.C. Kimlik, API Anahtarları, E-posta, Telefon, Kredi Kartı) maskeler
    ve tersine eşleme (unmasking) için yerel kasa (vault) oluşturur.
    """

    def __init__(self):
        self.analyzer = AnalyzerEngine()
        self.anonymizer = AnonymizerEngine()
        self._add_custom_recognizers()
        # Spacy/Presidio boru hattını başlatırken bir kez ısıt (cold-start gecikmesini önler)
        self.analyzer.analyze(
            text="warmup test@example.com",
            entities=["TC_KIMLIK", "API_KEY", "EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD"],
            language="en"
        )

    def _add_custom_recognizers(self):
        # 1. T.C. Kimlik No Tespiti (11 haneli kural: sıfır ile başlayamaz)
        tc_pattern = Pattern(
            name="tc_kimlik_pattern",
            regex=r"\b[1-9][0-9]{10}\b",
            score=0.85
        )
        tc_recognizer = PatternRecognizer(
            supported_entity="TC_KIMLIK",
            patterns=[tc_pattern]
        )
        self.analyzer.registry.add_recognizer(tc_recognizer)

        # 2. Standart LLM / Cloud API Key Tespiti (sk-..., ghp_..., AIza... vb.)
        api_pattern = Pattern(
            name="api_key_pattern",
            regex=r"(?:sk-[a-zA-Z0-9_\-]{20,}|ghp_[a-zA-Z0-9]{36}|AIza[0-9A-Za-z-_]{35})",
            score=0.95
        )
        api_recognizer = PatternRecognizer(
            supported_entity="API_KEY",
            patterns=[api_pattern]
        )
        self.analyzer.registry.add_recognizer(api_recognizer)

        # 3. Türkiye Telefon Numarası Tespiti (+90 5xx xxx xx xx, 05xx xxx xx xx vb.)
        tr_phone_pattern = Pattern(
            name="tr_phone_pattern",
            regex=r"(?:\+90|0)?\s*5[0-9]{2}[\s\-]?[0-9]{3}[\s\-]?[0-9]{2}[\s\-]?[0-9]{2}\b",
            score=0.85
        )
        tr_phone_recognizer = PatternRecognizer(
            supported_entity="PHONE_NUMBER",
            patterns=[tr_phone_pattern]
        )
        self.analyzer.registry.add_recognizer(tr_phone_recognizer)

    def mask(self, text: str) -> Tuple[str, Dict[str, str]]:
        """
        Metindeki hassas verileri maskeler ve geri dönüştürmek için eşleme sözlüğü üretir.
        """
        if not text:
            return "", {}

        # Hassas varlıkları analiz et
        results = self.analyzer.analyze(
            text=text,
            entities=["TC_KIMLIK", "API_KEY", "EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD"],
            language="en"  # Türkçe varlıklar özel regex'ler ve TR modellerle zenginleştirilecek
        )

        # Sonuçları metindeki başlangıç sırasına göre ve çakışmaları engellemek için sırala
        sorted_results = sorted(results, key=lambda x: (x.start, -x.score, -(x.end - x.start)))
        
        # Çakışan (overlapping) aralıkları ayıkla
        filtered_results = []
        last_end = -1
        for item in sorted_results:
            if item.start >= last_end:
                filtered_results.append(item)
                last_end = item.end

        vault_mapping: Dict[str, str] = {}
        offset = 0
        masked_text = text

        for idx, item in enumerate(filtered_results):
            original_val = text[item.start:item.end]
            placeholder = f"[{item.entity_type}_{idx + 1}]"
            vault_mapping[placeholder] = original_val

            # Metin içi dinamik yer değiştirme (kaymaları hesaplayarak)
            start_pos = item.start + offset
            end_pos = item.end + offset
            masked_text = masked_text[:start_pos] + placeholder + masked_text[end_pos:]
            offset += len(placeholder) - len(original_val)

        return masked_text, vault_mapping

    @staticmethod
    def summarize_entity_types(vault_mapping: Dict[str, str]) -> Dict[str, int]:
        """
        Kasa eşleme tablosundaki yer tutuculardan (ör. [TC_KIMLIK_1]) hangi veri
        türünden kaç adet yakalandığını hesaplar.
        """
        counts: Dict[str, int] = {}
        for placeholder in vault_mapping.keys():
            inner = placeholder.strip("[]")
            entity_type = "_".join(inner.split("_")[:-1])
            if entity_type:
                counts[entity_type] = counts.get(entity_type, 0) + 1
        return counts

    @staticmethod
    def is_valid_tc_checksum(tc_no: str) -> bool:
        """
        Resmi T.C. Kimlik Numarası algoritmik doğrulaması (11 hane + 10. ve 11. hane modül kontrolü).
        """
        if not tc_no or len(tc_no) != 11 or not tc_no.isdigit() or tc_no[0] == "0":
            return False
        digits = [int(d) for d in tc_no]
        odd_sum = sum(digits[0:9:2])
        even_sum = sum(digits[1:8:2])
        digit_10 = ((odd_sum * 7) - even_sum) % 10
        digit_11 = sum(digits[:10]) % 10
        return digits[9] == digit_10 and digits[10] == digit_11

    def unmask(self, masked_text: str, vault_mapping: Dict[str, str]) -> str:
        """
        LLM'den dönen yanıttaki yer tutucuları gerçek verilerle tekrar eşler.
        """
        if not masked_text or not vault_mapping:
            return masked_text

        restored_text = masked_text
        for placeholder, original in vault_mapping.items():
            restored_text = restored_text.replace(placeholder, original)
        return restored_text
