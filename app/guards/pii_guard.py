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
