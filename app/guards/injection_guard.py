import re
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
                "pattern": r"(?i)(ignore|disregard|forget)\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|rules)",
                "weight": 0.85,
                "reason": "Direct instruction override attempt"
            },
            {
                "pattern": r"(?i)(you\s+are\s+now|act\s+as)\s+(DAN|unrestricted|jailbroken|an\s+evil|developer\s+mode)",
                "weight": 0.90,
                "reason": "Roleplay/Jailbreak persona adoption"
            },
            {
                "pattern": r"(?i)(system\s*prompt|system\s*message|developer\s*instructions)\s*:",
                "weight": 0.75,
                "reason": "System prompt spoofing attempt"
            },
            {
                "pattern": r"(?i)(reveal|show|print|output)\s+(your\s+)?(system\s+prompt|hidden\s+instructions|base\s+prompt)",
                "weight": 0.80,
                "reason": "System prompt extraction attempt"
            },
            {
                "pattern": r"(?i)(önceki|tüm)\s+(talimatları|kuralları)\s+(unut|yoksay|boşver)",
                "weight": 0.85,
                "reason": "Turkish instruction override attempt"
            },
            {
                "pattern": r"(?i)(sistem\s+talimatlarını|sistem\s+mesajını)\s+(göster|yazdır|açıkla)",
                "weight": 0.80,
                "reason": "Turkish system prompt extraction attempt"
            }
        ]

    def scan(self, text: str) -> Tuple[bool, float, List[str]]:
        """
        Gelen metni analiz eder.
        Dönüş: (is_blocked, threat_score, reasons)
        """
        if not text:
            return False, 0.0, []

        reasons = []
        threat_score = 0.0

        # Heuristic analiz
        for item in self.heuristic_patterns:
            if re.search(item["pattern"], text):
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
