import uuid
from typing import Dict, Optional


class MemoryVault:
    """
    Oturum / İstek bazlı güvenli bellek kasası (Vault Cache).
    Hassas PII eşleme tablosunu istemciye ifşa etmeden sunucu tarafında tutar
    ve unmasking işlemi sonrası bellekten derhal siler (Zero-Leakage).
    Üretim ortamında Redis ile dağıtık çalışacak şekilde tasarlanmıştır.
    """

    def __init__(self):
        self._storage: Dict[str, Dict[str, str]] = {}

    def store(self, mapping: Dict[str, str]) -> str:
        """Eşleme sözlüğünü kaydeder ve benzersiz bir vault_id (UUID) döner."""
        req_id = str(uuid.uuid4())
        self._storage[req_id] = mapping
        return req_id

    def retrieve_and_purge(self, req_id: str) -> Optional[Dict[str, str]]:
        """Veriyi çeker ve bellekten derhal siler (Zero-Leakage İlkesi)."""
        return self._storage.pop(req_id, None)

    def size(self) -> int:
        """Mevcut aktif oturum sayısı."""
        return len(self._storage)


vault_store = MemoryVault()
