import os
import hmac
import time
import hashlib
from fastapi import Request, Header, HTTPException

GATEWAY_SERVICE_SECRET = os.environ.get(
    "GATEWAY_SERVICE_SECRET",
    "dev-gateway-service-secret-change-me"
).encode()

NONCE_EXPIRY = 120
_nonce_store: dict[str, float] = {}


def _cleanup_nonces() -> None:
    now = time.time()
    expired = [nonce for nonce, created_at in _nonce_store.items() if now - created_at > NONCE_EXPIRY]
    for nonce in expired:
        _nonce_store.pop(nonce, None)


async def verify_gateway_request(
    request: Request,
    x_gateway_timestamp: str = Header(None),
    x_gateway_nonce: str = Header(None),
    x_gateway_signature: str = Header(None),
    x_user_id: str = Header(None),
    x_user_email: str = Header(None),
    x_user_roles: str = Header(None),
):
    """Verify that the request was signed by the API Gateway.

    This prevents users from bypassing the Gateway and calling public Render
    microservice URLs directly.
    """
    if not x_gateway_timestamp or not x_gateway_nonce or not x_gateway_signature:
        raise HTTPException(status_code=401, detail="Missing Gateway signature")

    try:
        ts = int(x_gateway_timestamp)
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid Gateway timestamp")

    now = int(time.time())
    if abs(now - ts) > 60:
        raise HTTPException(status_code=401, detail="Gateway timestamp expired")

    _cleanup_nonces()
    if x_gateway_nonce in _nonce_store:
        raise HTTPException(status_code=401, detail="Gateway nonce already used")

    body = await request.body()
    body_str = body.decode() if body else ""
    canonical = f"{request.method}|{request.url.path}|{x_gateway_timestamp}|{x_gateway_nonce}|{body_str}"
    expected = hmac.new(GATEWAY_SERVICE_SECRET, canonical.encode(), hashlib.sha256).hexdigest()

    if not hmac.compare_digest(expected, x_gateway_signature):
        raise HTTPException(status_code=401, detail="Invalid Gateway signature")

    _nonce_store[x_gateway_nonce] = time.time()

    return {
        "user_id": x_user_id or "",
        "email": x_user_email or "",
        "roles": [role for role in (x_user_roles or "").split(",") if role],
    }
