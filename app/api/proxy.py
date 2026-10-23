import time
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from app.guards.pii_guard import PIIGuard
from app.guards.injection_guard import InjectionGuard
from app.services.llm_service import LLMService
from app.core.vault import vault_store
from app.core.db import log_request

router = APIRouter(tags=["LLM Secure Proxy"])

pii_guard = PIIGuard()
injection_guard = InjectionGuard(threshold=0.70)
llm_service = LLMService()


class ChatRequest(BaseModel):
    prompt: str = Field(..., description="Kullanıcıdan gelen ham sorgu metni")
    model: Optional[str] = Field("gpt-3.5-turbo", description="Hedef LLM modeli")


class TokenUsage(BaseModel):
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int


class ChatResponse(BaseModel):
    status: str = "SUCCESS"
    threat_score: float = 0.0
    pii_detected_count: int = 0
    gateway_overhead_ms: float
    llm_latency_ms: float
    total_latency_ms: float
    tokens: TokenUsage
    response: str


@router.post("/chat/secure", response_model=ChatResponse)
@router.post("/v1/chat/secure", response_model=ChatResponse)
async def secure_chat(req: ChatRequest):
    """
    1. Inbound Guard: Prompt Injection & Jailbreak Tehdit Taraması (403 Forbidden & Audit Log)
    2. Outbound Guard: PII Maskeleme & Zero-Leakage Memory Vault Oturumu
    3. Asenkron LLM İletişimi: Güvenli veri iletimi ve token takibi
    4. Outbound Unmasking: Tek kullanımlık kasa çözümü ve otomatik imha
    5. Telemetri: SQLite audit_logs tablosuna asenkron metrik kaydı
    """
    request_start = time.perf_counter()

    # 1. Inbound Guard: Güvenlik Tehdit Taraması
    is_blocked, threat_score, reasons = injection_guard.scan(req.prompt)
    if is_blocked:
        overhead_ms = round((time.perf_counter() - request_start) * 1000, 2)
        # Tehditi veritabanına logla
        log_request("BLOCKED", threat_score, 0, overhead_ms, 0.0, 0)

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "Security Policy Violation",
                "message": "Prompt injection or policy violation detected.",
                "threat_score": threat_score,
                "reasons": reasons,
                "latency_ms": overhead_ms
            }
        )

    # 2. Outbound Guard: PII Maskeleme
    pii_start = time.perf_counter()
    masked_prompt, mapping = pii_guard.mask(req.prompt)
    pii_latency_ms = round((time.perf_counter() - pii_start) * 1000, 2)
    pii_count = len(mapping)

    # Hassas eşlemeyi sunucu kasasında sakla (istemciye sızdırılmaz)
    vault_id = vault_store.store(mapping)

    # 3. Asenkron LLM İletişimi (Hedef modele sadece maskelenmiş veri gider)
    llm_start = time.perf_counter()
    llm_result = await llm_service.generate_response(prompt=masked_prompt, model=req.model)
    llm_latency_ms = round((time.perf_counter() - llm_start) * 1000, 2)

    # 4. Outbound Guard: Unmasking (Yanıttaki etiketleri geri açma ve kasayı silme)
    cached_mapping = vault_store.retrieve_and_purge(vault_id) or {}
    final_output = pii_guard.unmask(llm_result["content"], cached_mapping)

    total_latency_ms = round((time.perf_counter() - request_start) * 1000, 2)
    gateway_overhead_ms = round(total_latency_ms - llm_latency_ms, 2)
    total_tokens = llm_result["total_tokens"]

    # Başarılı isteği veritabanına logla
    log_request("SUCCESS", threat_score, pii_count, gateway_overhead_ms, llm_latency_ms, total_tokens)

    return ChatResponse(
        status="SUCCESS",
        threat_score=threat_score,
        pii_detected_count=pii_count,
        gateway_overhead_ms=gateway_overhead_ms,
        llm_latency_ms=llm_latency_ms,
        total_latency_ms=total_latency_ms,
        tokens=TokenUsage(
            prompt_tokens=llm_result["prompt_tokens"],
            completion_tokens=llm_result["completion_tokens"],
            total_tokens=total_tokens
        ),
        response=final_output
    )
