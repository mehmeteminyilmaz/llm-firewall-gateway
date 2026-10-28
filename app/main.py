import time
from contextlib import asynccontextmanager
from fastapi import FastAPI
import uvicorn

from app.core.vault import vault_store
from app.core.db import init_db
from app.api.proxy import router as proxy_router
from app.core.config import settings


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Uygulama başlarken SQLite veritabanını ve audit_logs tablosunu hazırla
    init_db()
    yield


app = FastAPI(
    title="Enterprise LLM Guardrail & Gateway",
    description="Faz 5: OpenAI SDK Uyumlu, Rate-Limited, Maliyet & PII Analitik Destekli Kurumsal Güvenlik Ağ Geçidi",
    version="1.0.0",
    lifespan=lifespan,
)


# UTF-8 Charset Middleware (Türkçe karakterlerin ve JSON çıktılarının bozulmaması için)
@app.middleware("http")
async def add_utf8_charset(request, call_next):
    response = await call_next(request)
    content_type = response.headers.get("content-type", "")
    if "application/json" in content_type and "charset" not in content_type:
        response.headers["content-type"] = "application/json; charset=utf-8"
    return response


# Proxy Router dahil et
app.include_router(proxy_router)


@app.get("/")
async def root():
    return {
        "service": "Enterprise LLM Guardrail & Gateway",
        "version": "1.0.0",
        "phase": "Faz 5 - Enterprise Hardening, OpenAI Drop-in Proxy & Full LLMOps Observability",
        "status": "online",
        "endpoints": {
            "secure_chat": "/v1/chat/secure",
            "openai_compatible": "/v1/chat/completions",
            "health": "/health",
            "docs": "/docs",
        },
    }


@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "active_vault_sessions": vault_store.size(),
        "rate_limit_window_sec": vault_store.rate_limit_window_sec,
        "rate_limit_max_requests": vault_store.rate_limit_requests,
        "timestamp": time.time(),
    }


if __name__ == "__main__":
    uvicorn.run("app.main:app", host=settings.HOST, port=settings.PORT, reload=settings.DEBUG)
