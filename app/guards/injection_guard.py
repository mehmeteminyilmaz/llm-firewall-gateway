import re
import unicodedata
from typing import Tuple, List, Dict, Any


class InjectionGuard:
    """
    Inbound Guard: Prompt Injection & Jailbreak Tespit Motoru.
    Kullanıcının sistem yönergelerini aşmaya (Jailbreak) veya modeli manipüle etmeye
    (Prompt Injection) yönelik girişimlerini kural bazlı (heuristic) ve semantik
    tehdit skorlaması ile tespit eder.
    """

    def __init__(self, threshold: float = 0.70):
        self.threshold = threshold

        # 1. Bilinen kritik jailbreak ve injection kalıpları (Regex tabanlı katman)
        self.heuristic_patterns: List[Dict[str, Any]] = [
            {
                "pattern": r"(?i)(ignore|disregard|forget|override|bypass)\s+(all\s+|every\s+|any\s+|the\s+)?(of\s+)?(your\s+|the\s+)?(previous|prior|above|earlier|initial|system|safety)\s+(instructions?|prompts?|rules?|guidelines?|constraints?)",
                "weight": 0.85,
                "reason": "Direct instruction override attempt"
            },
            {
                "pattern": r"(?i)(you\s+are\s+now|act\s+as|pretend\s+to\s+be|simulate|enter)\s+(a\s+|an\s+)?(DAN|STAN|DUDE|AIM|unrestricted|jailbroken|evil|developer\s+mode|god\s+mode|sudo\s+mode|unfiltered)",
                "weight": 0.90,
                "reason": "Roleplay/Jailbreak persona adoption"
            },
            {
                "pattern": r"(?i)(do\s+anything\s+now|stay\s+in\s+character|no\s+ethical\s+boundaries|without\s+any\s+restrictions|bypass\s+all\s+filters)",
                "weight": 0.85,
                "reason": "Unrestricted mode / safety bypass directive"
            },
            {
                "pattern": r"(?i)(\[system\]|\[inst\]|<<sys>>|<\|im_start\|>system|(system\s*prompt|system\s*message|developer\s*instructions)\s*:)",
                "weight": 0.80,
                "reason": "System prompt spoofing / delimiter injection attempt"
            },
            {
                "pattern": r"(?i)(reveal|show|print|output|repeat|dump|leak|tell\s+me)\s+(all\s+|everything\s+)?(in\s+|about\s+)?(your\s+|the\s+)?(system\s+prompt|hidden\s+instructions|base\s+prompt|initial\s+instructions|secret\s+rules|verbatim\s+prompt)",
                "weight": 0.80,
                "reason": "System prompt extraction attempt"
            },
            {
                "pattern": r"(?i)(hypothetical\s+scenario|for\s+educational\s+purposes\s+only|in\s+a\s+fictional\s+world).*(malware|ransomware|keylogger|exploit|sql\s+injection|hack|bypass\s+auth)",
                "weight": 0.85,
                "reason": "Hypothetical/fictional framing for malicious payload"
            },
            {
                "pattern": r"(?i)(decode|translate|execute)\s+(this\s+|the\s+following\s+)?(base64|hex|rot13)\s*(payload|string|command|instruction)?",
                "weight": 0.75,
                "reason": "Obfuscated payload execution attempt"
            },
            {
                "pattern": r"(?i)(önceki|tüm|bütün|yukarıdaki)\s+(talimatları|kuralları|yönergeleri|kısıtlamaları)\s+(unut|yoksay|boşver|devre\s+dışı\s+bırak|iptal\s+et)",
                "weight": 0.85,
                "reason": "Turkish instruction override attempt"
            },
            {
                "pattern": r"(?i)(sistem\s+talimatlarını|sistem\s+mesajını|gizli\s+promptu|başlangıç\s+komutlarını).*?(göster|yazdır|açıkla|ifşa\s+et|söyle)",
                "weight": 0.80,
                "reason": "Turkish system prompt extraction attempt"
            },
            {
                "pattern": r"(?i)(geliştirici\s+moduna|kısıtlamasız\s+moda|dan\s+moduna|filtresiz\s+moda)\s+(geç|gir|aktif\s+et)",
                "weight": 0.90,
                "reason": "Turkish jailbreak mode activation attempt"
            }
        ]

        # Regex'leri bir kez derle (her istekte yeniden derleme maliyetini önler)
        for item in self.heuristic_patterns:
            item["compiled"] = re.compile(item["pattern"])

    # Görünmez / sıfır genişlikli karakterler (ör. "I\u200bgnore" ile filtre atlatma girişimleri)
    _INVISIBLE_CHARS = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff\u00ad]")

    @classmethod
    def normalize(cls, text: str) -> str:
        """
        Obfuscation (gizleme) tabanlı atlatma girişimlerine karşı metni normalize eder:
        - NFKC: tam genişlikli / stilize Unicode harfleri (ör. 'Ｉｇｎｏｒｅ') ASCII karşılığına çevirir
        - Sıfır genişlikli ve yön kontrol karakterlerini siler
        - Ardışık boşlukları tek boşluğa indirger
        """
        text = unicodedata.normalize("NFKC", text)
        text = cls._INVISIBLE_CHARS.sub("", text)
        return re.sub(r"\s+", " ", text).strip()

    def scan(self, text: str) -> Tuple[bool, float, List[str]]:
        """
        Gelen metni analiz eder.
        Dönüş: (is_blocked, threat_score, reasons)
        """
        if not text:
            return False, 0.0, []

        text = self.normalize(text)
        reasons = []
        threat_score = 0.0

        # Heuristic analiz
        for item in self.heuristic_patterns:
            if item["compiled"].search(text):
                threat_score = max(threat_score, item["weight"])
                reasons.append(item["reason"])

        # Çoklu şüpheli anahtar kelime yoğunluğu kontrolü
        suspicious_keywords = [
            "base64", "bypass", "jailbreak", "override", "payload",
            "exploit", "unfiltered", "raw output", "kuralları çiğne"
        ]
        matched_kw = [kw for kw in suspicious_keywords if kw in text.lower()]
        if len(matched_kw) >= 2:
            threat_score = max(threat_score, 0.75)
            reasons.append(f"Suspicious keyword density: {', '.join(matched_kw)}")

        threat_score = round(threat_score, 2)
        is_blocked = threat_score >= self.threshold

        return is_blocked, threat_score, reasons
