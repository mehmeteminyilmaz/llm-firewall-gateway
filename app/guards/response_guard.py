import re
from typing import Tuple, List, Optional


class ResponseGuard:
    """
    Outbound Response Guardrail:
    Hedef LLM'den dönen yanıtların güvenliğini denetler:
    1. Canary Token Tespiti (Sistem Prompt Sızıntısı / Honeypot):
       Sistem promptuna gizlice eklenen canary belirtecinin yanıtta ifşa olup olmadığını denetler.
    2. Sistem Talimatı İfşa Kalıpları (System Prompt Echo / Leakage):
       Modelin 'My initial instructions are...', 'Sistem talimatlarım şunlardır:' gibi
       iç yönergeleri dışarı sızdırmasını yakalar.
    3. Zararlı Exploit / Saldırı Çıktıları (Harmful Payload Generation):
       Model jailbreak olsa dahi tehlikeli reverse shell, zararlı payload veya yıkıcı komut
       üretmesini engelleyen güvenlik süzgeci.
    """

    def __init__(self):
        # Sistem talimatı sızıntısı kalıpları
        self.leakage_patterns = [
            re.compile(r"(?i)(my\s+(secret\s+)?(system\s+prompt|initial\s+instructions|base\s+prompt|hidden\s+rules)\s+(is|are)\s*[:=])"),
            re.compile(r"(?i)(here\s+(is|are)\s+the\s+(secret\s+)?(system\s+prompt|raw\s+instructions|developer\s+instructions))"),
            re.compile(r"(?i)(sistem\s+talimatlarım\s*(şunlardır|aşağıdadır|:))"),
            re.compile(r"(?i)(gizli\s+kurallarım\s*(şunlardır|aşağıdaki\s+gibidir|:))"),
        ]

        # Yüksek riskli zararlı çıktı kalıpları (Reverse shell, yıkıcı exploit payload'ları)
        self.exploit_patterns = [
            re.compile(r"(?i)(/bin/sh\s+-i\s+>&|/bin/bash\s+-i\s+>&|\bnc\s+-e\s+/bin/(ba)?sh)"),
            re.compile(r"(?i)(powershell(?:\.exe)?\s+.*-(?:enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,})"),
            re.compile(r"(?i)(Invoke-Expression\s*\(New-Object\s+Net\.WebClient\)\.DownloadString)"),
        ]

    def scan(self, response_text: str, canary_token: Optional[str] = None) -> Tuple[bool, float, List[str]]:
        """
        Model yanıtını analiz eder.
        Dönüş: (is_violation, threat_score, reasons)
        """
        if not response_text:
            return False, 0.0, []

        reasons = []
        threat_score = 0.0

        # 1. Canary Token (Honeypot) Kontrolü
        if canary_token and canary_token in response_text:
            threat_score = 1.0
            reasons.append(f"Canary token leakage detected (System prompt compromised)")

        # 2. Sistem Talimatı Sızıntısı Kontrolü
        for pattern in self.leakage_patterns:
            if pattern.search(response_text):
                threat_score = max(threat_score, 0.85)
                reasons.append("System prompt verbatim leakage pattern detected")
                break

        # 3. Zararlı Exploit / Payload Üretim Kontrolü
        for pattern in self.exploit_patterns:
            if pattern.search(response_text):
                threat_score = max(threat_score, 0.90)
                reasons.append("High-risk exploit or reverse-shell payload generated in output")
                break

        threat_score = round(threat_score, 2)
        is_violation = threat_score >= 0.70

        return is_violation, threat_score, reasons
