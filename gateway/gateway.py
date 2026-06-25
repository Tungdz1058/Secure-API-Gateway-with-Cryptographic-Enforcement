from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import httpx
import os
import time
import asyncio
import random
import logging
import hmac
import hashlib
import secrets

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("gateway")

app = FastAPI(title="API Gateway")

# ========== CORS ==========
# Chỉ cho frontend chính thức + localhost khi test. Không dùng wildcard *.vercel.app.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:5500",
        "https://secure-api-gateway-with-cryptograph.vercel.app",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ========== CONFIG ==========
CACHE_TTL = 60
MAX_RETRIES = 5
RETRY_STATUS = {429, 502, 503, 504}
BACKOFF_BASE = 1.0
BACKOFF_CAP = 20.0
TIMEOUT = httpx.Timeout(connect=10.0, read=55.0, write=20.0, pool=10.0)
LIMITS = httpx.Limits(max_connections=20, max_keepalive_connections=10, keepalive_expiry=30.0)

# Secret nội bộ Gateway -> Auth Service
INTERNAL_AUTH_SECRET = os.environ.get(
    "INTERNAL_AUTH_SECRET",
    "dev-internal-auth-secret-change-me"
).encode()

# Secret nội bộ Gateway -> Microservices
GATEWAY_SERVICE_SECRET = os.environ.get(
    "GATEWAY_SERVICE_SECRET",
    "dev-gateway-service-secret-change-me"
).encode()

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
    "transfer": os.environ.get("TRANSFER_SERVICE_URL", "https://bank-transfer.onrender.com"),
    "account": os.environ.get("ACCOUNT_SERVICE_URL", "https://bank-account.onrender.com"),
    "admin": os.environ.get("ADMIN_SERVICE_URL", "https://bank-admin.onrender.com"),
}

# ========== ROLE REQUIREMENTS ==========
ROLE_REQUIREMENTS = {
    "admin": ["admin"],
    "transfer": ["user", "admin"],
    "account": ["user", "admin"],
}

PREFIX_SERVICES = ["auth"]


def make_hmac(secret: bytes, method: str, path: str, timestamp: str, nonce: str, body: str) -> str:
    canonical = f"{method}|{path}|{timestamp}|{nonce}|{body}"
    return hmac.new(secret, canonical.encode(), hashlib.sha256).hexdigest()


def _retry_delay(attempt: int, response: httpx.Response | None) -> float:
    if response is not None:
        retry_after = response.headers.get("retry-after")
        if retry_after:
            try:
                return min(float(retry_after), BACKOFF_CAP)
            except ValueError:
                pass
    base = min(BACKOFF_BASE * (2 ** attempt), BACKOFF_CAP)
    return base + random.uniform(0, base * 0.3)


async def request_with_retry(method: str, url: str, *, headers: dict = None,
                             content: bytes | str = None,
                             max_retries: int = MAX_RETRIES) -> httpx.Response:
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
    body_bytes = await request.body()
    body_str = body_bytes.decode() if body_bytes else ""

    verified_user = ""
    verified_email = ""
    verified_roles: list[str] = []

    # ===== AUTHENTICATION & AUTHORIZATION =====
    # Frontend chỉ gửi Bearer token. Gateway tự ký HMAC nội bộ khi hỏi Auth Service.
    if service in ROLE_REQUIREMENTS:
        authorization = request.headers.get("authorization")
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")

        required_roles = ROLE_REQUIREMENTS[service]

        original_path = f"/api/{service}/{path}"
        original_method = request.method
        internal_timestamp = str(int(time.time()))
        internal_nonce = secrets.token_hex(16)
        internal_signature = make_hmac(
            INTERNAL_AUTH_SECRET,
            original_method,
            original_path,
            internal_timestamp,
            internal_nonce,
            body_str,
        )

        auth_headers = {
            "Authorization": authorization,
            "Content-Type": "application/json",
            "X-Required-Role": ",".join(required_roles),
            "X-Gateway-Timestamp": internal_timestamp,
            "X-Gateway-Nonce": internal_nonce,
            "X-Gateway-Signature": internal_signature,
            "X-Original-Path": original_path,
            "X-Original-Method": original_method,
        }

        auth_url = f"{SERVICE_MAP['auth']}/auth/verify"
        logger.info("🔑 Sending internally signed request to Auth Service")

        try:
            verify_response = await request_with_retry(
                "POST", auth_url, headers=auth_headers, content=body_str
            )
        except (httpx.ConnectError, httpx.ConnectTimeout):
            raise HTTPException(status_code=503, detail="Auth Service unavailable")
        except (httpx.ReadTimeout, httpx.PoolTimeout):
            raise HTTPException(status_code=504, detail="Auth Service timeout")

        if verify_response.status_code != 200:
            try:
                error_detail = verify_response.json().get("detail", "Authentication failed")
            except Exception:
                error_detail = verify_response.text[:100]
            raise HTTPException(
                status_code=verify_response.status_code if verify_response.status_code in (401, 403) else 403,
                detail=error_detail,
            )

        verify_data = verify_response.json()
        jwt_verified = verify_data.get("jwt_verified", False)
        hmac_verified = verify_data.get("hmac_verified", False)
        session_active = verify_data.get("session_active", False)
        verified_roles = verify_data.get("roles", []) or []
        verified_user = verify_data.get("user", "") or ""
        verified_email = verify_data.get("email", "") or ""

        if not jwt_verified:
            raise HTTPException(status_code=401, detail="JWT verification failed")
        if not hmac_verified:
            raise HTTPException(status_code=401, detail="Internal Gateway HMAC verification failed")
        if not session_active:
            raise HTTPException(status_code=401, detail="Session not active - please login")
        if not any(role in verified_roles for role in required_roles):
            raise HTTPException(status_code=403, detail=f"Role required: {required_roles}")

        logger.info("✅ JWT, session, role and internal HMAC verified")

    # ===== FORWARD REQUEST =====
    if service in PREFIX_SERVICES:
        forward_path = f"{service}/{path}"
    else:
        forward_path = path

    headers = dict(request.headers)
    headers.pop("host", None)

    # Không forward HMAC cũ từ client. Client không còn giữ secret.
    for h in [
        "x-timestamp", "x-nonce", "x-signature",
        "x-gateway-timestamp", "x-gateway-nonce", "x-gateway-signature",
        "x-original-path", "x-original-method",
    ]:
        headers.pop(h, None)

    # Với business microservice, Gateway ký request nội bộ để chặn gọi thẳng service.
    if service in ROLE_REQUIREMENTS:
        service_path = f"/{forward_path}"
        service_timestamp = str(int(time.time()))
        service_nonce = secrets.token_hex(16)
        service_signature = make_hmac(
            GATEWAY_SERVICE_SECRET,
            request.method,
            service_path,
            service_timestamp,
            service_nonce,
            body_str,
        )
        headers["X-Gateway-Timestamp"] = service_timestamp
        headers["X-Gateway-Nonce"] = service_nonce
        headers["X-Gateway-Signature"] = service_signature
        headers["X-User-Id"] = verified_user
        headers["X-User-Email"] = verified_email
        headers["X-User-Roles"] = ",".join(verified_roles)

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

    if response.status_code == 429:
        raise HTTPException(status_code=429, detail=f"Service {service} đang quá tải, thử lại sau")

    try:
        data = response.json()
    except Exception:
        return {"error": "Service error", "status": response.status_code, "body": response.text[:200]}

    if response.status_code >= 400:
        raise HTTPException(status_code=response.status_code, detail=data.get("detail", data))
    return data


@app.get("/health")
async def health():
    return {"status": "ok", "services": list(SERVICE_MAP.keys())}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
