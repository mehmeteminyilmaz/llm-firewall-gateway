"""
Pytest ortak yapılandırması.
- Testler gerçek SOC veritabanını (llmops.db) kirletmesin diye geçici bir SQLite dosyası kullanılır.
- Her testten önce rate limit sayaçları sıfırlanır (testler birbirinin kotasını tüketmesin).
"""
import os
import sys
import tempfile
from pathlib import Path

# app modülleri import edilmeden ÖNCE ayarlanmalı
os.environ["SQLITE_DB_PATH"] = str(Path(tempfile.gettempdir()) / "llm_guardrail_test.db")
os.environ.setdefault("GATEWAY_API_KEYS", "")
sys.path.insert(0, str(Path(__file__).resolve().parent))

import pytest  # noqa: E402

from app.core.vault import vault_store  # noqa: E402


@pytest.fixture(autouse=True)
def _reset_rate_limits():
    vault_store.reset_rate_limits()
    yield
    vault_store.reset_rate_limits()

