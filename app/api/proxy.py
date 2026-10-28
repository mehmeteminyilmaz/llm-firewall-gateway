import time
import uuid
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, Field

from app.core.config import settings
from app.core.db import log_request
from app.core.vault import vault_store
from app.guards.injection_guard import InjectionGuard
from app.guards.pii_guard import PIIGuard
from app.services.llm_service import LLMService, UpstreamLLMError

router = APIRouter(tags=["LLM Secure Proxy"])

# Singleton servis örnekleri (Presidio/Spacy modeli süreç başına yalnızca bir kez yüklenir)
pii_guard = PIIGuard()
injection_guard = InjectionGuard(threshold=settings.INJECTION_THRESHOLD)
llm_service = LLMService()

# İçeriği güvenlik taramasından geçirilecek roller (system mesajı uygulama sahibine aittir, güvenilir kabul edilir)
UNTRUSTED_ROLES = {"user", "tool", "function"}


# ---------------------------------------------------------------------------
# Şemalar
# ---------------------------------------------------------------------------
class ChatRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=settings.MAX_PROMPT_CHARS,
                        description="Kullanıcıdan gelen ham sorgu metni")
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
    llm_mode: str = "simulated"
    tokens: TokenUsage
    response: str


class OpenAIMessage(BaseModel):
    role: str = "user"
    content: str = ""


class OpenAIChatCompletionRequest(BaseModel):
    model: str = "gpt-3.5-turbo"
    messages: List[OpenAIMessage] = Field(..., min_length=1)
    temperature: Optional[float] = 0.3
    stream: Optional[bool] = False


# ---------------------------------------------------------------------------
# Kimlik doğrulama (opsiyonel)
# ---------------------------------------------------------------------------
def resolve_client(request: Request) -> str:
    """
    GATEWAY_API_KEYS tanımlıysa Bearer / X-API-Key zorunludur.
    Dönüş değeri rate limiting için istemci kimliği olarak kullanılır.
    """
    auth = request.headers.get("authorization", "")
    token = auth[7:].strip() if auth.lower().startswith("bearer ") else request.headers.get("x-api-key", "").strip()

    if settings.GATEWAY_API_KEYS:
        if token not in settings.GATEWAY_API_KEYS:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"error": "Unauthorized", "message": "Valid gateway API key required."},
                headers={"WWW-Authenticate": "Bearer"},
            )
        return f"key:{token[:8]}"
    return f"ip:{request.client.host if request.client else 'local'}"


# ---------------------------------------------------------------------------
# Ortak güvenli işlem hattı
# ---------------------------------------------------------------------------
async def _guarded_completion(
    messages: List[Dict[str, str]],
    model: str,
    client_id: str,
    response: Response,
    temperature: float = 0.3,
) -> ChatResponse:
    """
    0. Rate Limiting (HTTP 429)
    1. Inbound Guard: güvenilmeyen tüm mesajlarda injection taraması (HTTP 403)
    2. Outbound Guard: tüm mesajlarda PII maskeleme + Zero-Leakage Vault
    3. Asenkron LLM çağrısı (hata durumunda HTTP 502)
    4. Unmasking + kasanın HER DURUMDA imhası (try/finally)
    5. Zero-content audit log (threadpool üzerinden, event loop'u bloklamadan)
    """
    request_start = time.perf_counter()
    model = model or llm_service.default_model

    # 0. Rate limit
    allowed, remaining = vault_store.check_rate_limit(client_id)
    response.headers["X-RateLimit-Remaining"] = str(remaining)
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={"error": "Rate Limit Exceeded",
                    "message": "Maximum request quota exceeded for this window. Please retry shortly."},
            headers={"Retry-After": str(vault_store.rate_limit_window_sec), "X-RateLimit-Remaining": "0"},
        )

    # Toplam boyut kontrolü (DoS / aşırı NER maliyeti koruması)
    if sum(len(m["content"]) for m in messages) > settings.MAX_PROMPT_CHARS:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail={"error": "Payload Too Large",
                    "message": f"Total message content exceeds {settings.MAX_PROMPT_CHARS} characters."},
        )

    # 1. Inbound Guard
    threat_score, reasons = 0.0, []
    for m in messages:
        if m["role"] in UNTRUSTED_ROLES:
            blocked, score, why = injection_guard.scan(m["content"])
            threat_score = max(threat_score, score)
            reasons.extend(r for r in why if r not in reasons)

    if threat_score >= injection_guard.threshold:
        overhead_ms = round((time.perf_counter() - request_start) * 1000, 2)
        await run_in_threadpool(
            log_request, "BLOCKED", threat_score, 0, overhead_ms, 0.0, 0, 0.0, {}, model
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

    # 2. Outbound Guard: her mesajı maskele, yer tutucu numaraları mesajlar arasında çakışmasın
    mapping: Dict[str, str] = {}
    masked_messages: List[Dict[str, str]] = []
    for m in messages:
        masked_text, part = pii_guard.mask(m["content"], start_index=len(mapping))
        mapping.update(part)
        masked_messages.append({"role": m["role"], "content": masked_text})

    pii_count = len(mapping)
    pii_types = pii_guard.summarize_entity_types(mapping)
    vault_id = vault_store.store(mapping)

    # 3-4. LLM çağrısı + kasanın her koşulda imhası
    llm_start = time.perf_counter()
    try:
        llm_result = await llm_service.generate_response(
            model=model, messages=masked_messages, temperature=temperature if temperature is not None else 0.3
        )
    except UpstreamLLMError as exc:
        vault_store.retrieve_and_purge(vault_id)
        overhead_ms = round((time.perf_counter() - request_start) * 1000, 2)
        await run_in_threadpool(
            log_request, "UPSTREAM_ERROR", threat_score, pii_count, overhead_ms, 0.0, 0, 0.0, pii_types, model
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={"error": "Upstream LLM Error", "message": str(exc)},
        )
    finally:
        cached_mapping = vault_store.retrieve_and_purge(vault_id) or mapping

    llm_latency_ms = round((time.perf_counter() - llm_start) * 1000, 2)
    final_output = pii_guard.unmask(llm_result["content"], cached_mapping)

    total_latency_ms = round((time.perf_counter() - request_start) * 1000, 2)
    gateway_overhead_ms = round(max(0.01, total_latency_ms - llm_latency_ms), 2)
    total_tokens = llm_result["total_tokens"]
    estimated_cost_usd = llm_result.get("estimated_cost_usd", 0.0)

    await run_in_threadpool(
        log_request, "SUCCESS", threat_score, pii_count, gateway_overhead_ms, llm_latency_ms,
        total_tokens, estimated_cost_usd, pii_types, model,
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
        llm_mode=llm_result.get("mode", "simulated"),
        tokens=TokenUsage(
            prompt_tokens=llm_result["prompt_tokens"],
            completion_tokens=llm_result["completion_tokens"],
            total_tokens=total_tokens,
        ),
        response=final_output,
    )


# ---------------------------------------------------------------------------
# Endpoint'ler
# ---------------------------------------------------------------------------
@router.post("/chat/secure", response_model=ChatResponse)
@router.post("/v1/chat/secure", response_model=ChatResponse)
async def secure_chat(req: ChatRequest, response: Response, client_id: str = Depends(resolve_client)):
    """Tek prompt'luk güvenli sohbet endpoint'i (detaylı güvenlik metrikleriyle)."""
    return await _guarded_completion(
        messages=[{"role": "user", "content": req.prompt}],
        model=req.model,
        client_id=client_id,
        response=response,
    )


@router.post("/v1/chat/completions")
async def openai_compatible_completions(
    req: OpenAIChatCompletionRequest, response: Response, client_id: str = Depends(resolve_client)
):
    """
    OpenAI SDK ve LangChain uyumlu drop-in proxy endpoint'i.
    Tüm mesaj geçmişi (system/user/assistant) korunarak, maskelenmiş şekilde hedef LLM'e iletilir.
    """
    if req.stream:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "Streaming Not Supported",
                    "message": "stream=true is not supported yet; the full response must be unmasked before delivery."},
        )

    secure_res = await _guarded_completion(
        messages=[{"role": m.role, "content": m.content} for m in req.messages],
        model=req.model,
        client_id=client_id,
        response=response,
        temperature=req.temperature,
    )

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
                "message": {"role": "assistant", "content": secure_res.response},
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
            "llm_mode": secure_res.llm_mode,
        },
    }
