"""Faz 6b: TR IBAN (MOD-97), JWT ve Bearer token maskeleme testleri."""
import base64
import json

from app.api import proxy
from app.guards.pii_guard import PIIGuard, _iban_mod97_ok

pii = proxy.pii_guard


def make_tr_iban(bban22: str) -> str:
    """Geçerli kontrol hanelerine sahip sentetik TR IBAN üretir (T=29, R=27)."""
    check = 98 - (int(bban22 + "292700") % 97)
    return f"TR{check:02d}{bban22}"


def _b64(obj: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")


def make_jwt() -> str:
    # Çalışma anında üretilir (depoda gerçek görünümlü sabit jeton bulunmasın)
    return f"{_b64({'alg': 'HS256', 'typ': 'JWT'})}.{_b64({'sub': 'test-user', 'role': 'admin'})}.c2lnbmF0dXJlLWJ5dGVz"


VALID_IBAN = make_tr_iban("0006100519786457841326")


def test_valid_iban_helper_passes_mod97():
    assert _iban_mod97_ok(VALID_IBAN)
    assert not _iban_mod97_ok(VALID_IBAN[:-1] + str((int(VALID_IBAN[-1]) + 1) % 10))


def test_compact_and_spaced_iban_are_masked():
    spaced = " ".join([VALID_IBAN[:4]] + [VALID_IBAN[i:i + 4] for i in range(4, 24, 4)] + [VALID_IBAN[24:]])
    for form in (VALID_IBAN, spaced):
        masked, mapping = pii.mask(f"Havale hesabı {form} adına yapılsın")
        assert form not in masked
        assert any(k.startswith("[TR_IBAN_") for k in mapping), (form, mapping)
        assert list(mapping.values())[0] == form


def test_iban_with_bad_checksum_is_not_masked():
    bad = VALID_IBAN[:-1] + str((int(VALID_IBAN[-1]) + 1) % 10)
    _, mapping = pii.mask(f"Hesap {bad} geçersiz")
    assert not any(k.startswith("[TR_IBAN_") for k in mapping)


def test_jwt_and_bearer_tokens_are_masked():
    jwt = make_jwt()
    masked, mapping = pii.mask(f"Token: {jwt} ile giriş yapıldı")
    assert jwt not in masked and any(k.startswith("[JWT_TOKEN_") for k in mapping)

    bearer = "Authorization: Bearer abcDEF1234567890xyzABCDEF.tokenvalue-123"
    masked, mapping = pii.mask(bearer)
    assert "abcDEF1234567890xyzABCDEF" not in masked
    assert any(k.startswith("[BEARER_TOKEN_") for k in mapping)


def test_ordinary_text_is_not_flagged():
    for text in ["TR ile başlayan kelimeler: TRAKTÖR, TRABZON", "Bearer of bad news", "eyJ yazan bir kelime"]:
        _, mapping = pii.mask(text)
        assert mapping == {}, (text, mapping)


def test_endpoint_reports_new_pii_types():
    from fastapi.testclient import TestClient
    from app.main import app

    r = TestClient(app).post("/v1/chat/secure", json={
        "prompt": f"IBAN {VALID_IBAN} ve token {make_jwt()} kaydedildi"})
    assert r.status_code == 200
    data = r.json()
    assert data["pii_types"].get("TR_IBAN") == 1 and data["pii_types"].get("JWT_TOKEN") == 1
    assert VALID_IBAN in data["response"]  # kullanıcıya dönen yanıtta unmask edilmiş olmalı
