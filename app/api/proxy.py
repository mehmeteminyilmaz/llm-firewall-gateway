import time
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from app.guards.pii_guard import PIIGuard
from app.guards.injection_guard import InjectionGuard
from app.services.llm_service import LLMService

router = APIRouter(tags=["LLM Secure Proxy"])

# Global guard and service instances
pii_guard = PIIGuard()
injection_guard = InjectionGuard(threshold=0.70)
llm_service = LLMService()


class ChatRequest(BaseModel):
    prompt: str = Field(..., description="Kullanıcıdan gelen ham sorgu metni")
    model: str = Field("gpt-3.5-turbo", description="Hedef LLM modeli")
    simulate: bool = Field(True, description="Simülasyon modunda mı çalıştırılsın?")


class ChatResponse(BaseModel):
    status: str = "APPROVED"
    threat_score: float = 0.0
    original_prompt_received: str
    masked_prompt_sent_to_llm: str
    response: str
    vault_mappings: Dict[str, str]
    latency_ms: float


@router.post("/chat/secure", response_model=ChatResponse)
@router.post("/v1/chat/secure", response_model=ChatResponse)
async def secure_chat(req: ChatRequest):
    """
    1. Inbound Guard: Prompt Injection & Jailbreak Tespiti (Tehdit varsa 403 ile keser)
    2. Outbound Guard: PII Maskeleme (T.C. Kimlik, API Key, E-posta vb.)
    3. LLM Çağrısı: Maskelenmiş verinin güvenli iletimi
    4. Unmasking: Yanıttaki yer tutucuları çözme
    """
    start_time = time.perf_counter()

    # 1. Inbound Guard: Prompt Injection & Jailbreak Analizi
    is_blocked, threat_score, threat_reasons = injection_guard.scan(req.prompt)

    if is_blocked:
        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "Security Policy Violation",
                "message": "Prompt injection or policy violation detected. Request terminated.",
                "threat_score": threat_score,
                "reasons": threat_reasons,
                "latency_ms": latency_ms
            }
        )

    # 2. Outbound Guard: PII Maskeleme
    masked_prompt, vault = pii_guard.mask(req.prompt)

    # 3. LLM Çağrısı (veya Simülasyon)
    llm_response = await llm_service.generate_response(
        prompt=masked_prompt,
        model=req.model,
        simulate=req.simulate
    )

    # 4. Geri Açma (Unmasking)
    final_response = pii_guard.unmask(llm_response, vault)

    latency_ms = round((time.perf_counter() - start_time) * 1000, 2)

    return ChatResponse(
        status="APPROVED",
        threat_score=threat_score,
        original_prompt_received=req.prompt,
        masked_prompt_sent_to_llm=masked_prompt,
        response=final_response,
        vault_mappings=vault,
        latency_ms=latency_ms
    )
