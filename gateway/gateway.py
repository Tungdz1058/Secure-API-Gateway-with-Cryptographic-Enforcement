from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import httpx
import os
import hashlib
import time
import asyncio
import random
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("gateway")

app = FastAPI(title="API Gateway")

# ========== CORS ==========
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "https://secure-api-gateway-with-cryptograph.vercel.app",
        "https://*.vercel.app",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ========== CONFIG ==========
CACHE_TTL = 60
MAX_RETRIES = 5            # số lần thử lại tối đa khi gặp 429 / lỗi tạm thời
RETRY_STATUS = {429, 502, 503, 504}  # các mã lỗi đáng để thử lại
BACKOFF_BASE = 1.0         # giây - cơ sở cho exponential backoff
BACKOFF_CAP = 20.0         # trần thời gian chờ mỗi lần (giây)

# Timeout chia nhỏ: connect nhanh nhưng cho phép đọc lâu (Render free cold-start)
TIMEOUT = httpx.Timeout(connect=10.0, read=55.0, write=20.0, pool=10.0)

# Giới hạn kết nối + bật keep-alive để tái sử dụng, tránh tạo handshake liên tục
LIMITS = httpx.Limits(max_connections=20, max_keepalive_connections=10,
                      keepalive_expiry=30.0)

# ========== SHARED HTTP CLIENT ==========
# Dùng chung 1 client cho toàn bộ vòng đời app -> giữ kết nối, giảm tải, giảm 429
http_client: httpx.AsyncClient | None = None


@app.on_event("startup")
async def _startup():
    global http_client
    http_client = httpx.AsyncClient(timeout=TIMEOUT, limits=LIMITS)
    logger.info("✅ Shared HTTP client started")


@app.on_event("shutdown")
async def _shutdown():
    global http_client
    if http_client:
        await http_client.aclose()
        logger.info("👋 Shared HTTP client closed")


# ========== SERVICE MAP ==========
SERVICE_MAP = {
    "auth": os.environ.get("AUTH_SERVICE_URL", "https://bank-auth.onrender.com"),
    "transfer": os.environ.get("TRANSFER_SERVICE_URL", "https://bank-transfer-vd1p.onrender.com"),
    "account": os.environ.get("ACCOUNT_SERVICE_URL", "https://bank-account-corr.onrender.com"),
    "admin": os.environ.get("ADMIN_SERVICE_URL", "https://bank-admin-ou0n.onrender.com"),
}

# ========== ROLE REQUIREMENTS ==========
ROLE_REQUIREMENTS = {
    "admin": ["admin"],
    "transfer": ["user", "admin"],
    "account": ["user", "admin"],
}

PREFIX_SERVICES = ["auth"]

# ========== CACHE ==========
role_cache = {}


def get_cache_key(token: str, nonce: str = None) -> str:
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    if nonce:
        return f"{token_hash}:{nonce}"
    return token_hash


def get_cached_roles(token: str, nonce: str = None):
    """Returns (roles, hmac_verified, jwt_verified, session_active)"""
    cache_key = get_cache_key(token, nonce)
    if cache_key in role_cache:
        cache_entry = role_cache[cache_key]
        if time.time() < cache_entry["expiry"]:
            return (
                cache_entry.get("roles", []),
                cache_entry.get("hmac_verified", False),
                cache_entry.get("jwt_verified", False),
                cache_entry.get("session_active", False),
            )
        else:
            del role_cache[cache_key]
    return None, None, None, None


def set_cached_roles(token: str, nonce: str, roles: list, hmac_verified: bool = True,
                     jwt_verified: bool = True, session_active: bool = True, ttl: int = CACHE_TTL):
    if not (hmac_verified and jwt_verified and session_active):
        logger.warning("⚠️ Not caching failed verification")
        return
    cache_key = get_cache_key(token, nonce)
    role_cache[cache_key] = {
        "roles": roles,
        "hmac_verified": hmac_verified,
        "jwt_verified": jwt_verified,
        "session_active": session_active,
        "expiry": time.time() + ttl,
    }
    logger.info(f"✅ Cached verification for nonce: {nonce}")


# ========== RETRY HELPER (dùng chung cho auth verify + forward) ==========
def _retry_delay(attempt: int, response: httpx.Response | None) -> float:
    """Tính thời gian chờ trước lần thử kế tiếp.
    Ưu tiên header Retry-After nếu service báo về, nếu không thì
    exponential backoff + jitter để tránh các client cùng dồn vào một thời điểm.
    """
    if response is not None:
        retry_after = response.headers.get("retry-after")
        if retry_after:
            try:
                return min(float(retry_after), BACKOFF_CAP)
            except ValueError:
                pass
    base = min(BACKOFF_BASE * (2 ** attempt), BACKOFF_CAP)
    return base + random.uniform(0, base * 0.3)  # thêm jitter


async def request_with_retry(method: str, url: str, *, headers: dict = None,
                             content: bytes | str = None,
                             max_retries: int = MAX_RETRIES) -> httpx.Response:
    """Gửi request qua shared client, tự thử lại khi gặp 429/5xx tạm thời
    hoặc lỗi kết nối/timeout (thường gặp khi service free đang cold-start)."""
    assert http_client is not None, "HTTP client chưa được khởi tạo"
    last_exc: Exception | None = None

    for attempt in range(max_retries):
        try:
            response = await http_client.request(
                method=method, url=url, headers=headers, content=content
            )
            if response.status_code in RETRY_STATUS and attempt < max_retries - 1:
                delay = _retry_delay(attempt, response)
                logger.warning(
                    f"⏳ {url} trả {response.status_code}, thử lại sau {delay:.1f}s "
                    f"(lần {attempt + 1}/{max_retries})"
                )
                await asyncio.sleep(delay)
                continue
            return response
        except (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout,
                httpx.PoolTimeout) as exc:
            last_exc = exc
            if attempt < max_retries - 1:
                delay = _retry_delay(attempt, None)
                logger.warning(
                    f"⏳ {url} lỗi {type(exc).__name__}, thử lại sau {delay:.1f}s "
                    f"(lần {attempt + 1}/{max_retries})"
                )
                await asyncio.sleep(delay)
                continue
            raise

    if last_exc:
        raise last_exc
    raise HTTPException(status_code=503, detail="Service unavailable after retries")


# ========== MAIN ROUTE ==========
@app.api_route("/api/{service}/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def gateway(request: Request, service: str, path: str):
    service_url = SERVICE_MAP.get(service)
    if not service_url:
        raise HTTPException(status_code=404, detail=f"Service {service} not found")

    logger.info(f"📨 Request: {request.method} /api/{service}/{path}")

    # Đọc body 1 lần, tái sử dụng cho cả verify lẫn forward (tránh đọc 2 lần)
    body_bytes = await request.body()

    # ===== AUTHENTICATION & AUTHORIZATION =====
    if service in ROLE_REQUIREMENTS:
        authorization = request.headers.get("authorization")
        if not authorization:
            raise HTTPException(status_code=401, detail="Missing Authorization header")

        token = authorization.split(" ")[1] if authorization.startswith("Bearer ") else None
        if not token:
            raise HTTPException(status_code=401, detail="Invalid Authorization header")

        required_roles = ROLE_REQUIREMENTS[service]
        required_role = required_roles[0]

        x_timestamp = request.headers.get("x-timestamp", "")
        x_nonce = request.headers.get("x-nonce", "")
        x_signature = request.headers.get("x-signature", "")

        if not x_timestamp or not x_nonce or not x_signature:
            raise HTTPException(status_code=401, detail="Missing HMAC headers")

        # ===== CHECK CACHE =====
        cached_roles, cached_hmac, cached_jwt, cached_session = get_cached_roles(token, x_nonce)
        if cached_roles is not None:
            logger.info(f"✅ Cache hit for nonce: {x_nonce}")
            if not cached_jwt:
                raise HTTPException(status_code=401, detail="JWT verification failed")
            if not cached_hmac:
                raise HTTPException(status_code=401, detail="Invalid HMAC signature")
            if not cached_session:
                raise HTTPException(status_code=401, detail="Session not active - please login")
            if not any(role in cached_roles for role in required_roles):
                raise HTTPException(status_code=403, detail=f"Role required: {required_roles}")
            logger.info("✅ Cache valid, skipping auth verification")
        else:
            # ===== CALL AUTH SERVICE =====
            body_str = body_bytes.decode() if body_bytes else ""
            auth_headers = {
                "Authorization": authorization,
                "Content-Type": "application/json",
                "X-Required-Role": required_role,
                "X-Timestamp": x_timestamp,
                "X-Nonce": x_nonce,
                "X-Signature": x_signature,
                "X-Original-Path": f"/api/{service}/{path}",
                "X-Original-Method": request.method,
            }

            logger.info("🔑 Sending to Auth Service for verification")
            auth_url = f"{SERVICE_MAP['auth']}/auth/verify"

            try:
                verify_response = await request_with_retry(
                    "POST", auth_url, headers=auth_headers, content=body_str
                )
            except (httpx.ConnectError, httpx.ConnectTimeout):
                raise HTTPException(status_code=503, detail="Auth Service unavailable")
            except (httpx.ReadTimeout, httpx.PoolTimeout):
                raise HTTPException(status_code=504, detail="Auth Service timeout")

            if verify_response.status_code != 200:
                error_detail = "Authentication failed"
                try:
                    error_detail = verify_response.json().get("detail", "Authentication failed")
                except Exception:
                    error_detail = verify_response.text[:100]
                raise HTTPException(status_code=verify_response.status_code
                                    if verify_response.status_code in (401, 403)
                                    else 403,
                                    detail=error_detail)

            verify_data = verify_response.json()
            logger.info("✅ Auth response received")

            hmac_verified = verify_data.get("hmac_verified", False)
            jwt_verified = verify_data.get("jwt_verified", False)
            session_active = verify_data.get("session_active", False)
            roles = verify_data.get("roles", [])

            if hmac_verified and jwt_verified and session_active:
                set_cached_roles(token, x_nonce, roles, hmac_verified, jwt_verified, session_active)
            else:
                logger.warning(f"⚠️ Not caching failed verification for nonce: {x_nonce}")

            if not jwt_verified:
                raise HTTPException(status_code=401, detail="JWT verification failed")
            if not hmac_verified:
                logger.warning(f"❌ HMAC verification failed: {request.method} /api/{service}/{path}")
                raise HTTPException(status_code=401, detail="Invalid HMAC signature")
            if not session_active:
                raise HTTPException(status_code=401, detail="Session not active - please login")
            if not any(role in roles for role in required_roles):
                raise HTTPException(status_code=403, detail=f"Role required: {required_roles}")

            logger.info("✅ All verifications passed")

    # ===== FORWARD REQUEST (giờ cũng có retry) =====
    if service in PREFIX_SERVICES:
        forward_path = f"{service}/{path}"
    else:
        forward_path = path

    headers = dict(request.headers)
    headers.pop("host", None)

    try:
        response = await request_with_retry(
            request.method,
            f"{service_url}/{forward_path}",
            headers=headers,
            content=body_bytes,
        )
    except (httpx.ConnectError, httpx.ConnectTimeout):
        raise HTTPException(status_code=503, detail=f"Service {service} unavailable")
    except (httpx.ReadTimeout, httpx.PoolTimeout):
        raise HTTPException(status_code=504, detail=f"Service {service} timeout")

    # Nếu sau khi retry vẫn 429 -> báo rõ để client biết đường chờ
    if response.status_code == 429:
        raise HTTPException(status_code=429, detail=f"Service {service} đang quá tải, thử lại sau")

    try:
        return response.json()
    except Exception:
        return {"error": "Service error", "status": response.status_code}


# ========== HEALTH CHECK ==========
@app.get("/health")
async def health():
    return {
        "status": "ok",
        "services": list(SERVICE_MAP.keys()),
        "cache_size": len(role_cache),
    }


@app.get("/cache/clear")
async def clear_cache():
    role_cache.clear()
    return {"message": "Cache cleared", "cache_size": 0}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
