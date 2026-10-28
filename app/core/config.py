import os
from pathlib import Path
from typing import List

from dotenv import load_dotenv

# Load .env file from project root
env_path = Path(__file__).resolve().parent.parent.parent / ".env"
load_dotenv(dotenv_path=env_path)


def _csv(value: str) -> List[str]:
    return [v.strip() for v in value.split(",") if v.strip()]


class Settings:
    PROJECT_NAME: str = "Enterprise LLM Guardrail & Gateway"
    VERSION: str = "1.1.0"
    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", "8000"))
    DEBUG: bool = os.getenv("DEBUG", "False").lower() in ("true", "1", "t")

    # Upstream LLM
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
    UPSTREAM_LLM_URL: str = os.getenv("UPSTREAM_LLM_URL", "https://api.openai.com/v1/chat/completions")
    DEFAULT_MODEL: str = os.getenv("DEFAULT_MODEL", "gpt-3.5-turbo")
    UPSTREAM_TIMEOUT_SEC: float = float(os.getenv("UPSTREAM_TIMEOUT_SEC", "30"))

    # Inbound Guard
    INJECTION_THRESHOLD: float = float(os.getenv("INJECTION_THRESHOLD", "0.70"))
    MAX_PROMPT_CHARS: int = int(os.getenv("MAX_PROMPT_CHARS", "20000"))

    # Rate limiting (sliding window)
    RATE_LIMIT_REQUESTS: int = int(os.getenv("RATE_LIMIT_REQUESTS", "30"))
    RATE_LIMIT_WINDOW_SEC: int = int(os.getenv("RATE_LIMIT_WINDOW_SEC", "60"))

    # Gateway kimlik doğrulaması: boş bırakılırsa kapalıdır (geliştirme modu).
    # Örn: GATEWAY_API_KEYS=team-a-key,team-b-key
    GATEWAY_API_KEYS: List[str] = _csv(os.getenv("GATEWAY_API_KEYS", ""))


settings = Settings()
