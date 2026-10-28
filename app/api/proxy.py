import time
import uuid
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, HTTPException, Request, Response, status
from pydantic import BaseModel, Field

from app.guards.pii_guard import PIIGuard
from app.guards.injection_guard import InjectionGuard
from app.services.llm_service import LLMService
from app.core.vault import vault_store
from app.core.db import log_request

router = APIRouter(tags=["LLM Secure Proxy"])

# Singleton servis örnekleri
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
    pii_types: Dict[str, int] = Field(default_factory=dict)
    gateway_overhead_ms: float
    llm_latency_ms: float
    total_latency_ms: float
    estimated_cost_usd: float = 0.0
    tokens: TokenUsage
    response: str


class OpenAIMessage(BaseModel):
    role: str = "user"
    content: str


class OpenAIChatCompletionRequest(BaseModel):
    model: str = "gpt-3.5-turbo"
    messages: List[OpenAIMessage]
    temperature: Optional[float] = 0.3


@router.post("/chat/secure", response_model=ChatResponse)
@router.post("/v1/chat/secure", response_model=ChatResponse)
async def secure_chat(req: ChatRequest, request: Request, response: Response):
    """
    Kurumsal Güvenli Ters Proxy Endpoint'i:
    0. Rate Limiting: Sliding-window hız sınırlandırması (HTTP 429)
    1. Inbound Guard: Prompt Injection & Jailbreak Tehdit Taraması (HTTP 403 & Audit Log)
    2. Outbound Guard: PII Maskeleme & Zero-Leakage Memory Vault Oturumu
    3. Asenkron LLM İletişimi: Güvenli veri iletimi, token ve USD maliyet takibi
    4. Outbound Unmasking: Tek kullanımlık kasa çözümü ve otomatik imha
    5. Telemetri: SQLite audit_logs tablosuna metrik, maliyet ve PII tür kaydı
    """
    request_start = time.perf_counter()
    client_ip = request.client.host if request.client else "local"

    # 0. Rate Limit Kontrolü
    allowed, remaining = vault_store.check_rate_limit(client_ip)
    response.headers["X-RateLimit-Remaining"] = str(remaining)
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "error": "Rate Limit Exceeded",
                "message": "Maximum request quota exceeded for this window. Please retry shortly.",
            },
        )

    # 1. Inbound Guard: Güvenlik Tehdit Taraması
    is_blocked, threat_score, reasons = injection_guard.scan(req.prompt)
    if is_blocked:
        overhead_ms = round((time.perf_counter() - request_start) * 1000, 2)
        log_request(
            status="BLOCKED",
            threat_score=threat_score,
            pii_count=0,
            gateway_latency=overhead_ms,
            llm_latency=0.0,
            total_tokens=0,
            estimated_cost_usd=0.0,
            pii_types={},
            model=req.model or "gpt-3.5-turbo",
        )

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "Security Policy Violation",
                "message": "Prompt injection or policy violation detected.",
                "threat_score": threat_score,
                "reasons": reasons,
                "latency_ms": overhead_ms,
            },
        )

    # 2. Outbound Guard: PII Maskeleme
    masked_prompt, mapping = pii_guard.mask(req.prompt)
    pii_count = len(mapping)
    pii_types = pii_guard.summarize_entity_types(mapping)

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
    gateway_overhead_ms = round(max(0.01, total_latency_ms - llm_latency_ms), 2)
    total_tokens = llm_result["total_tokens"]
    estimated_cost_usd = llm_result.get("estimated_cost_usd", 0.0)

    # Başarılı isteği veritabanına logla
    log_request(
        status="SUCCESS",
        threat_score=threat_score,
        pii_count=pii_count,
        gateway_latency=gateway_overhead_ms,
        llm_latency=llm_latency_ms,
        total_tokens=total_tokens,
        estimated_cost_usd=estimated_cost_usd,
        pii_types=pii_types,
        model=req.model or "gpt-3.5-turbo",
    )

    return ChatResponse(
        status="SUCCESS",
        threat_score=threat_score,
        pii_detected_count=pii_count,
        pii_types=pii_types,
        gateway_overhead_ms=gateway_overhead_ms,
        llm_latency_ms=llm_latency_ms,
        total_latency_ms=total_latency_ms,
        estimated_cost_usd=estimated_cost_usd,
        tokens=TokenUsage(
            prompt_tokens=llm_result["prompt_tokens"],
            completion_tokens=llm_result["completion_tokens"],
            total_tokens=total_tokens,
        ),
        response=final_output,
    )


@router.post("/v1/chat/completions")
async def openai_compatible_completions(req: OpenAIChatCompletionRequest, request: Request, response: Response):
    """
    OpenAI SDK ve LangChain Tam Uyumlu Drop-In Proxy Endpoint'i.
    Mevcut kurumsal uygulamalar kod değiştirmeden yalnızca base_url="http://localhost:8000/v1"
    tanımlayarak tüm Inbound & Outbound Guardrail katmanlarından faydalanır.
    """
    user_messages = [m.content for m in req.messages if m.role == "user"]
    combined_prompt = "\n".join(user_messages) if user_messages else (req.messages[-1].content if req.messages else "")

    secure_res = await secure_chat(
        ChatRequest(prompt=combined_prompt, model=req.model),
        request=request,
        response=response,
    )

    # Güvenlik telemetrisini HTTP başlıklarında (headers) raporla
    response.headers["X-Guardrail-Status"] = secure_res.status
    response.headers["X-Guardrail-Threat-Score"] = str(secure_res.threat_score)
    response.headers["X-Guardrail-PII-Masked"] = str(secure_res.pii_detected_count)
    response.headers["X-Guardrail-Overhead-Ms"] = str(secure_res.gateway_overhead_ms)

    return {
        "id": f"chatcmpl-{uuid.uuid4().hex[:12]}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": req.model,
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": secure_res.response,
                },
                "finish_reason": "stop",
            }
        ],
        "usage": {
            "prompt_tokens": secure_res.tokens.prompt_tokens,
            "completion_tokens": secure_res.tokens.completion_tokens,
            "total_tokens": secure_res.tokens.total_tokens,
        },
        "guardrail_metadata": {
            "threat_score": secure_res.threat_score,
            "pii_detected_count": secure_res.pii_detected_count,
            "pii_types": secure_res.pii_types,
            "gateway_overhead_ms": secure_res.gateway_overhead_ms,
            "estimated_cost_usd": secure_res.estimated_cost_usd,
        },
    }
