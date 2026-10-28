import time
import uuid
from typing import Dict, List, Optional, Tuple

from app.core.config import settings


class MemoryVault:
    """
    Oturum / İstek bazlı güvenli bellek kasası (Vault Cache) ve Rate Limiter.
    1. Zero-Leakage Session Storage: Hassas PII eşleme tablosunu istemciye ifşa etmeden
       sunucu tarafında tutar ve unmasking işlemi sonrası bellekten derhal siler.
    2. Sliding-Window Rate Limiting: İstemci / IP bazlı istek sıklığını denetler.
    Üretim ortamında Redis ile dağıtık çalışacak şekilde tasarlanmıştır.
    """

    def __init__(self, rate_limit_requests: int = 30, rate_limit_window_sec: int = 60):
        self._storage: Dict[str, Dict[str, str]] = {}
        self._rate_buckets: Dict[str, List[float]] = {}
        self.rate_limit_requests = rate_limit_requests
        self.rate_limit_window_sec = rate_limit_window_sec

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

    def check_rate_limit(self, client_id: str = "default") -> Tuple[bool, int]:
        """
        Sliding-window rate limiter.
        Dönüş: (is_allowed, remaining_quota)
        """
        now = time.time()
        window_start = now - self.rate_limit_window_sec
        timestamps = self._rate_buckets.get(client_id, [])
        # Süresi dolan kayıtları temizle
        valid_timestamps = [ts for ts in timestamps if ts > window_start]

        if len(valid_timestamps) >= self.rate_limit_requests:
            self._rate_buckets[client_id] = valid_timestamps
            return False, 0

        valid_timestamps.append(now)
        self._rate_buckets[client_id] = valid_timestamps
        remaining = max(0, self.rate_limit_requests - len(valid_timestamps))

        # Bellek şişmesini önlemek için pasif istemcilerin kovalarını periyodik temizle
        if len(self._rate_buckets) > 10_000:
            self._rate_buckets = {
                cid: ts for cid, ts in self._rate_buckets.items() if ts and ts[-1] > window_start
            }
        return True, remaining

    def reset_rate_limits(self) -> None:
        """Test ve sıfırlama amaçlı tüm rate limit sayaçlarını temizler."""
        self._rate_buckets.clear()


vault_store = MemoryVault(
    rate_limit_requests=settings.RATE_LIMIT_REQUESTS,
    rate_limit_window_sec=settings.RATE_LIMIT_WINDOW_SEC,
)
