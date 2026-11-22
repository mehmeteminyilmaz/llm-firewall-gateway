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
# Birim/entegrasyon testleri yerel .env dosyasındaki canlı LLM ayarlarından etkilenmesin
os.environ["OPENAI_API_KEY"] = ""
os.environ["LLM_API_KEY"] = ""
os.environ["GROQ_API_KEY"] = ""
os.environ["ANTHROPIC_API_KEY"] = ""
os.environ["OLLAMA_API_KEY"] = ""
sys.path.insert(0, str(Path(__file__).resolve().parent))

import pytest  # noqa: E402

from app.core.vault import vault_store  # noqa: E402
from app.api.proxy import reset_security_policy  # noqa: E402


@pytest.fixture(autouse=True)
def _reset_rate_limits():
    vault_store.reset_rate_limits()
    reset_security_policy()
    yield
    vault_store.reset_rate_limits()
    reset_security_policy()

