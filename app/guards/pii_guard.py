import os
import re
from typing import Dict, Optional, Tuple, List
from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_anonymizer import AnonymizerEngine


def _tc_checksum_ok(tc_no: str) -> bool:
    """Resmi T.C. Kimlik No algoritması (10. ve 11. hane modül kontrolü)."""
    if not tc_no or len(tc_no) != 11 or not tc_no.isdigit() or tc_no[0] == "0":
        return False
    d = [int(c) for c in tc_no]
    digit_10 = ((sum(d[0:9:2]) * 7) - sum(d[1:8:2])) % 10
    digit_11 = sum(d[:10]) % 10
    return d[9] == digit_10 and d[10] == digit_11


class TCKimlikRecognizer(PatternRecognizer):
    """
    11 haneli adayları yakalar, ardından resmi checksum ile doğrular.
    Sipariş/fatura numarası gibi rastgele 11 haneli sayılar maskelenmez (yanlış pozitif azaltımı).
    """

    def validate_result(self, pattern_text: str) -> Optional[bool]:
        return _tc_checksum_ok(pattern_text)


def _iban_mod97_ok(iban: str) -> bool:
    """ISO 13616 IBAN doğrulaması (MOD-97) ve Türkiye uzunluk kontrolü (26 karakter)."""
    s = re.sub(r"[\s-]", "", iban).upper()
    if not re.fullmatch(r"TR\d{24}", s):
        return False
    rearranged = s[4:] + s[:4]
    numeric = "".join(str(int(c, 36)) for c in rearranged)
    return int(numeric) % 97 == 1


class TRIBANRecognizer(PatternRecognizer):
    """TR IBAN adaylarını (boşluklu veya bitişik) yakalar ve MOD-97 ile doğrular."""

    def validate_result(self, pattern_text: str) -> Optional[bool]:
        return _iban_mod97_ok(pattern_text)


class PIIGuard:
    """
    Regex ve Presidio tabanlı hibrit PII Maskeleme ve Geri Dönüştürme Motoru.
    Hassas verileri (T.C. Kimlik, API Anahtarları, E-posta, Telefon, Kredi Kartı) maskeler
    ve tersine eşleme (unmasking) için yerel kasa (vault) oluşturur.
    """

    ENTITIES = [
        "TC_KIMLIK", "TR_IBAN", "API_KEY", "JWT_TOKEN", "BEARER_TOKEN",
        "EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD",
    ]

    def __init__(self):
        # Model açıkça seçilir: Presidio varsayılanı en_core_web_lg (~400 MB) sessizce indirmeye çalışır.
        # Maskeleme ağırlıklı olarak regex/algoritmik olduğundan küçük model yeterlidir.
        model_name = os.getenv("SPACY_MODEL", "en_core_web_sm")
        nlp_engine = NlpEngineProvider(nlp_configuration={
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": model_name}],
        }).create_engine()
        self.analyzer = AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=["en"])
        self.anonymizer = AnonymizerEngine()
        self._add_custom_recognizers()
        # Spacy/Presidio boru hattını başlatırken bir kez ısıt (cold-start gecikmesini önler)
        self.analyzer.analyze(
            text="warmup test@example.com",
            entities=self.ENTITIES,
            language="en"
        )

    def _add_custom_recognizers(self):
        # 1. T.C. Kimlik No Tespiti (11 haneli kural: sıfır ile başlayamaz)
        tc_pattern = Pattern(
            name="tc_kimlik_pattern",
            regex=r"\b[1-9][0-9]{10}\b",
            score=0.85
        )
        tc_recognizer = TCKimlikRecognizer(
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
            regex=r"(?<![\d+])(?:\+90|0)?\s*5[0-9]{2}[\s\-]?[0-9]{3}[\s\-]?[0-9]{2}[\s\-]?[0-9]{2}(?!\d)",
            score=0.85
        )
        tr_phone_recognizer = PatternRecognizer(
            supported_entity="PHONE_NUMBER",
            patterns=[tr_phone_pattern]
        )
        self.analyzer.registry.add_recognizer(tr_phone_recognizer)

        # 4. Türkiye IBAN (TR + 24 hane, boşluklu/bitişik) - MOD-97 doğrulamalı
        iban_pattern = Pattern(
            name="tr_iban_pattern",
            regex=r"\bTR\d{2}(?:[ \-]?\d{4}){5}[ \-]?\d{2}\b",
            score=0.95
        )
        self.analyzer.registry.add_recognizer(
            TRIBANRecognizer(supported_entity="TR_IBAN", patterns=[iban_pattern])
        )

        # 5. JWT (header.payload.signature) - base64url, header/payload JSON '{' = 'eyJ'
        jwt_pattern = Pattern(
            name="jwt_pattern",
            regex=r"\beyJ[A-Za-z0-9_\-]{5,}\.eyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}",
            score=0.95
        )
        self.analyzer.registry.add_recognizer(
            PatternRecognizer(supported_entity="JWT_TOKEN", patterns=[jwt_pattern])
        )

        # 6. Authorization: Bearer <token> (opak erişim jetonları)
        bearer_pattern = Pattern(
            name="bearer_pattern",
            regex=r"(?i)\bbearer\s+[A-Za-z0-9\-._~+/]{20,}=*",
            score=0.9
        )
        self.analyzer.registry.add_recognizer(
            PatternRecognizer(supported_entity="BEARER_TOKEN", patterns=[bearer_pattern])
        )

    def mask(self, text: str, start_index: int = 0) -> Tuple[str, Dict[str, str]]:
        """
        Metindeki hassas verileri maskeler ve geri dönüştürmek için eşleme sözlüğü üretir.
        start_index: Çok mesajlı isteklerde yer tutucu numaralarının çakışmaması için başlangıç ofseti.
        """
        if not text:
            return "", {}

        # Hassas varlıkları analiz et
        results = self.analyzer.analyze(
            text=text,
            entities=self.ENTITIES,
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
            placeholder = f"[{item.entity_type}_{start_index + idx + 1}]"
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
        return _tc_checksum_ok(tc_no)

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
