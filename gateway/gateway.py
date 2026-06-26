from fastapi import FastAPI, Request, HTTPException, Header
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
import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("gateway")

app = FastAPI(title="API Gateway")

# ========== CORS ==========
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

# Bật/tắt endpoint demo lấy HMAC signature
# Render env:
# ENABLE_SECURITY_DEMO=true  -> bật demo
# ENABLE_SECURITY_DEMO=false -> tắt demo
ENABLE_SECURITY_DEMO = os.environ.get("ENABLE_SECURITY_DEMO", "false").lower() == "true"

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


# ========== HMAC HELPERS ==========
def make_hmac(secret: bytes, method: str, path: str, timestamp: str, nonce: str, body: str) -> str:
    """
    Canonical request:
    METHOD|PATH|TIMESTAMP|NONCE|BODY
    """
    canonical = f"{method.upper()}|{path}|{timestamp}|{nonce}|{body}"
    return hmac.new(secret, canonical.encode(), hashlib.sha256).hexdigest()


def build_demo_curl(
    url: str,
    method: str,
    authorization: str,
    timestamp: str,
    nonce: str,
    signature: str,
    user_id: str,
    user_roles: str,
    body: str = "",
) -> str:
    if method.upper() == "GET":
        return f"""curl -i {url} \\
  -H "Authorization: {authorization}" \\
  -H "X-Gateway-Timestamp: {timestamp}" \\
  -H "X-Gateway-Nonce: {nonce}" \\
  -H "X-Gateway-Signature: {signature}" \\
  -H "X-User-Id: {user_id}" \\
  -H "X-User-Roles: {user_roles}"
"""

    return f"""curl -i {url} \\
  -X {method.upper()} \\
  -H "Authorization: {authorization}" \\
  -H "Content-Type: application/json" \\
  -H "X-Gateway-Timestamp: {timestamp}" \\
  -H "X-Gateway-Nonce: {nonce}" \\
  -H "X-Gateway-Signature: {signature}" \\
  -H "X-User-Id: {user_id}" \\
  -H "X-User-Roles: {user_roles}" \\
  -d '{body}'
"""


# ========== RETRY ==========
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


async def request_with_retry(
    method: str,
    url: str,
    *,
    headers: dict = None,
    content: bytes | str = None,
    max_retries: int = MAX_RETRIES,
) -> httpx.Response:
    assert http_client is not None, "HTTP client chưa được khởi tạo"
    last_exc: Exception | None = None

    for attempt in range(max_retries):
        try:
            response = await http_client.request(
                method=method,
                url=url,
                headers=headers,
                content=content,
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

        except (
            httpx.ConnectError,
            httpx.ConnectTimeout,
            httpx.ReadTimeout,
            httpx.PoolTimeout,
        ) as exc:
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


# ==========================================================
# SECURITY DEMO ENDPOINT 1
# Tạo signed request hợp lệ cho Account Service
# Dùng để test:
# - HMAC hợp lệ -> 200
# - sửa 1 ký tự signature -> 401 Invalid Gateway signature
# - replay lại sau khi timestamp hết hạn -> 401 Gateway timestamp expired
# ==========================================================
@app.get("/api/security-demo/signed-account-request")
async def create_signed_account_request(
    authorization: str = Header(None),
):
    if not ENABLE_SECURITY_DEMO:
        raise HTTPException(status_code=404, detail="Not found")

    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")

    method = "GET"
    path = "/ACC001"
    body = ""
    timestamp = str(int(time.time()))
    nonce = secrets.token_hex(16)

    signature = make_hmac(
        GATEWAY_SERVICE_SECRET,
        method,
        path,
        timestamp,
        nonce,
        body,
    )

    # User demo hiện tại của bạn
    demo_user_id = "auth0|6a2cd06b23a8f6df6a9e26e3"
    demo_roles = "user"

    microservice_url = f"{SERVICE_MAP['account']}{path}"

    valid_curl = build_demo_curl(
        url=microservice_url,
        method=method,
        authorization=authorization,
        timestamp=timestamp,
        nonce=nonce,
        signature=signature,
        user_id=demo_user_id,
        user_roles=demo_roles,
        body=body,
    )

    # Sửa 1 ký tự cuối của signature để test fake signature
    tampered_signature = signature[:-1] + ("0" if signature[-1] != "0" else "1")

    fake_signature_curl = build_demo_curl(
        url=microservice_url,
        method=method,
        authorization=authorization,
        timestamp=timestamp,
        nonce=nonce,
        signature=tampered_signature,
        user_id=demo_user_id,
        user_roles=demo_roles,
        body=body,
    )

    return {
        "demo": "signed account request",
        "warning": "Use for security demo only. Disable ENABLE_SECURITY_DEMO after testing.",
        "method": method,
        "microservice_url": microservice_url,
        "path": path,
        "body": body,
        "timestamp": timestamp,
        "nonce": nonce,
        "signature": signature,
        "tampered_signature_one_char_changed": tampered_signature,
        "expected_valid_result": "200 OK if token/session/user mapping is valid",
        "expected_fake_signature_result": "401 Invalid Gateway signature",
        "valid_curl": valid_curl,
        "fake_signature_curl": fake_signature_curl,
    }


# ==========================================================
# SECURITY DEMO ENDPOINT 2
# Tạo signed request hợp lệ cho Transfer Service
# Dùng để test:
# - body gốc amount=10000 + signature hợp lệ
# - sửa body amount=10001 nhưng giữ signature cũ -> 401 Invalid Gateway signature
# - sửa 1 ký tự signature -> 401 Invalid Gateway signature
# - replay cùng timestamp/nonce/signature -> kiểm tra nonce/timestamp behavior
# ==========================================================
@app.get("/api/security-demo/signed-transfer-request")
async def create_signed_transfer_request(
    authorization: str = Header(None),
):
    if not ENABLE_SECURITY_DEMO:
        raise HTTPException(status_code=404, detail="Not found")

    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")

    method = "POST"
    path = "/transfer"

    original_body_obj = {
        "from_account": "ACC001",
        "to_account": "ACC002",
        "amount": 10000,
        "description": "hmac integrity demo",
    }

    # Phải dùng cùng kiểu serialize khi ký và khi gửi curl
    original_body = json.dumps(original_body_obj, separators=(",", ":"), sort_keys=True)

    timestamp = str(int(time.time()))
    nonce = secrets.token_hex(16)

    signature = make_hmac(
        GATEWAY_SERVICE_SECRET,
        method,
        path,
        timestamp,
        nonce,
        original_body,
    )

    # User demo hiện tại của bạn
    demo_user_id = "auth0|6a2cd06b23a8f6df6a9e26e3"
    demo_roles = "user"

    microservice_url = f"{SERVICE_MAP['transfer']}{path}"

    valid_curl = build_demo_curl(
        url=microservice_url,
        method=method,
        authorization=authorization,
        timestamp=timestamp,
        nonce=nonce,
        signature=signature,
        user_id=demo_user_id,
        user_roles=demo_roles,
        body=original_body,
    )

    # Sửa 1 ký tự trong body: amount 10000 -> 10001
    tampered_body_obj = {
        "from_account": "ACC001",
        "to_account": "ACC002",
        "amount": 10001,
        "description": "hmac integrity demo",
    }

    tampered_body = json.dumps(tampered_body_obj, separators=(",", ":"), sort_keys=True)

    tampered_body_curl = build_demo_curl(
        url=microservice_url,
        method=method,
        authorization=authorization,
        timestamp=timestamp,
        nonce=nonce,
        signature=signature,
        user_id=demo_user_id,
        user_roles=demo_roles,
        body=tampered_body,
    )

    # Sửa 1 ký tự cuối của signature
    tampered_signature = signature[:-1] + ("0" if signature[-1] != "0" else "1")

    fake_signature_curl = build_demo_curl(
        url=microservice_url,
        method=method,
        authorization=authorization,
        timestamp=timestamp,
        nonce=nonce,
        signature=tampered_signature,
        user_id=demo_user_id,
        user_roles=demo_roles,
        body=original_body,
    )

    return {
        "demo": "signed transfer request",
        "warning": "Use for security demo only. Disable ENABLE_SECURITY_DEMO after testing.",
        "method": method,
        "microservice_url": microservice_url,
        "path": path,
        "original_body": original_body_obj,
        "tampered_body": tampered_body_obj,
        "changed_field": "amount",
        "changed_from": 10000,
        "changed_to": 10001,
        "timestamp": timestamp,
        "nonce": nonce,
        "signature_created_from_original_body": signature,
        "tampered_signature_one_char_changed": tampered_signature,
        "expected_valid_result": "200 OK or business validation result, but not Invalid Gateway signature",
        "expected_tampered_body_result": "401 Invalid Gateway signature",
        "expected_fake_signature_result": "401 Invalid Gateway signature",
        "valid_curl": valid_curl,
        "tampered_body_curl": tampered_body_curl,
        "fake_signature_curl": fake_signature_curl,
        "replay_test_instruction": "Run valid_curl twice. If nonce cache exists, second request should be rejected. If not, replay is limited by timestamp expiration.",
    }


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
                "POST",
                auth_url,
                headers=auth_headers,
                content=body_str,
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
                status_code=verify_response.status_code
                if verify_response.status_code in (401, 403)
                else 403,
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

    # Không forward các header nội bộ do client tự chèn vào.
    # Gateway phải tự tạo lại các header này.
    blocked_client_headers = [
        "x-timestamp",
        "x-nonce",
        "x-signature",
        "x-gateway-timestamp",
        "x-gateway-nonce",
        "x-gateway-signature",
        "x-original-path",
        "x-original-method",
        "x-user-id",
        "x-user-email",
        "x-user-roles",
    ]

    for h in blocked_client_headers:
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
        return {
            "error": "Service error",
            "status": response.status_code,
            "body": response.text[:200],
        }

    if response.status_code >= 400:
        raise HTTPException(status_code=response.status_code, detail=data.get("detail", data))

    return data


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "services": list(SERVICE_MAP.keys()),
        "security_demo_enabled": ENABLE_SECURITY_DEMO,
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
