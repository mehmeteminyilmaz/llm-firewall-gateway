import time
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel
import uvicorn

from app.guards.pii_guard import PIIGuard
from app.guards.injection_guard import InjectionGuard
from app.api.proxy import router as proxy_router
from app.core.config import settings

app = FastAPI(
    title="Enterprise LLM Guardrail & Gateway",
    description="Faz 2: Inbound Guard (Prompt Injection & Jailbreak Tespiti) & PII Maskeleme",
    version="0.2.0"
)

# UTF-8 Charset Middleware (Türkçe karakterlerin ve JSON çıktılarının bozulmaması için)
@app.middleware("http")
async def add_utf8_charset(request, call_next):
    response = await call_next(request)
    content_type = response.headers.get("content-type", "")
    if "application/json" in content_type and "charset" not in content_type:
        response.headers["content-type"] = "application/json; charset=utf-8"
    return response

# Router ekle
app.include_router(proxy_router)

# Bağımsız nesneler (Direct fallback)
pii_guard = PIIGuard()
injection_guard = InjectionGuard(threshold=0.70)


class ChatRequest(BaseModel):
    prompt: str
    model: str = "gpt-3.5-turbo"


@app.get("/")
async def root():
    return {
        "service": "Enterprise LLM Guardrail & Gateway",
        "phase": "Faz 2 - Inbound Guard (Injection & Jailbreak Shield) + PII Masking",
        "status": "online",
        "endpoints": {
            "secure_chat": "/v1/chat/secure",
            "docs": "/docs"
        }
    }


@app.get("/health")
async def health():
    return {"status": "healthy", "timestamp": time.time()}


if __name__ == "__main__":
    uvicorn.run("app.main:app", host=settings.HOST, port=settings.PORT, reload=settings.DEBUG)
