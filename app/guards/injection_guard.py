import re
import unicodedata
from typing import Tuple, List, Dict, Any, Optional

from app.guards.semantic_guard import SemanticGuard


class InjectionGuard:
    """
    Inbound Guard: 3-Katmanlı Hibrit Prompt Injection & Jailbreak Tespit Motoru.

    Kademeli Savunma Mimarisi (Cascaded Defense-in-Depth):
    - Katman 1 (L1 - Deterministik Regex & İmza Motoru, ~0.04 ms):
      Bilinen kesin saldırı imzalarını ve Unicode gizleme (obfuscation) girişimlerini anında yakalar.
    - Katman 2 (L2 - Leksikal Yoğunluk Analizi, ~0.02 ms):
      Çoklu şüpheli anahtar kelime yoğunluğunu tespit eder.
    - Katman 3 (L3 - Semantik Vektör Benzerliği & ML Sınıflandırıcısı, ~0.45 ms):
      L1/L2 kural katmanını atlatmak için kelimeleri değiştirilmiş (paraphrased) veya dolaylı
      kurgulanmış saldırıları TF-IDF Alt-Kelime Vektör Uzayı, Kontrastif Kosinüs Benzerliği
      ve L2 Lojistik Regresyon modeli ile anlamsal olarak yakalar.
    """

    def __init__(self, threshold: float = 0.70, enable_semantic: bool = True):
        self.threshold = threshold
        self.enable_semantic = enable_semantic
        self.custom_blacklist: List[str] = []
        self.semantic_guard: Optional[SemanticGuard] = (
            SemanticGuard(semantic_threshold=threshold) if enable_semantic else None
        )

        # 1. Katman 1 (L1): Bilinen kritik jailbreak ve injection kalıpları (Regex tabanlı katman)
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

    def scan_detailed(self, text: str) -> Dict[str, Any]:
        """
        Gelen metni 3 katmanlı kademeli mimariyle analiz eder ve hangi katmanın
        tetiklendiğini içeren detaylı denetim sözlüğü döndürür.
        """
        if not text:
            return {
                "is_blocked": False,
                "threat_score": 0.0,
                "reasons": [],
                "detection_layer": "CLEAN",
                "semantic_details": {},
            }

        normalized = self.normalize(text)
        reasons: List[str] = []
        threat_score = 0.0
        detection_layer = "CLEAN"
        semantic_details: Dict[str, Any] = {}

        # Katman 0 (L0): Kurumsal Özel Kara Liste (Custom Blacklist - Gizli Proje / Yasaklı Terimler)
        if self.custom_blacklist:
            norm_lower = normalized.lower()
            for term in self.custom_blacklist:
                clean_term = term.strip()
                if clean_term and clean_term.lower() in norm_lower:
                    threat_score = max(threat_score, 0.95)
                    reasons.append(f"Corporate custom blacklist violation: '{clean_term}'")
                    detection_layer = "L0_BLACKLIST"

        # Katman 1 (L1): Deterministik Regex İmza Analizi
        for item in self.heuristic_patterns:
            if item["compiled"].search(normalized):
                if item["weight"] > threat_score:
                    detection_layer = "L1_REGEX"
                threat_score = max(threat_score, item["weight"])
                reasons.append(item["reason"])

        # Katman 2 (L2): Çoklu şüpheli anahtar kelime yoğunluğu kontrolü
        suspicious_keywords = [
            "base64", "bypass", "jailbreak", "override", "payload",
            "exploit", "unfiltered", "raw output", "kuralları çiğne"
        ]
        matched_kw = [kw for kw in suspicious_keywords if kw in normalized.lower()]
        if len(matched_kw) >= 2:
            if 0.75 > threat_score:
                detection_layer = "L2_LEXICAL"
            threat_score = max(threat_score, 0.75)
            reasons.append(f"Suspicious keyword density: {', '.join(matched_kw)}")

        # Katman 3 (L3): Semantik Vektör Benzerliği & ML Sınıflandırıcısı
        # Yalnızca L0/L1/L2 eşiği aşmadıysa çalışır (Fast-path short-circuit optimizasyonu)
        if self.enable_semantic and threat_score < self.threshold:
            if self.semantic_guard is None:
                self.semantic_guard = SemanticGuard(semantic_threshold=self.threshold)
            sem_score, sem_reason, sem_meta = self.semantic_guard.score(normalized)
            semantic_details = sem_meta
            if sem_score > threat_score and sem_reason:
                threat_score = sem_score
                reasons.append(sem_reason)
                detection_layer = "L3_SEMANTIC_ML"

        threat_score = round(threat_score, 2)
        is_blocked = threat_score >= self.threshold

        return {
            "is_blocked": is_blocked,
            "threat_score": threat_score,
            "reasons": reasons,
            "detection_layer": detection_layer if is_blocked or threat_score > 0 else "CLEAN",
            "semantic_details": semantic_details,
        }

    def scan(self, text: str) -> Tuple[bool, float, List[str]]:
        """
        Gelen metni analiz eder.
        Dönüş: (is_blocked, threat_score, reasons)
        """
        res = self.scan_detailed(text)
        return res["is_blocked"], res["threat_score"], res["reasons"]
