import os
import time
import hashlib
import hmac
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import jwt
import redis
from jwt.exceptions import InvalidTokenError, ExpiredSignatureError

print("=== AUTH SERVICE INITIALIZING ===")

# ========== REDIS / IN-MEMORY ==========
REDIS_URL = os.environ.get("REDIS_URL", "")
print(f"REDIS_URL: {REDIS_URL if REDIS_URL else 'NOT SET'}")

USE_REDIS = False
redis_client = None

if REDIS_URL:
    try:
        redis_client = redis.from_url(REDIS_URL, decode_responses=True)
        redis_client.ping()
        USE_REDIS = True
        print("✅ Redis connected")
    except Exception as e:
        print(f"❌ Redis not available: {e}")
        print("⚠️ Using in-memory storage instead")

if not USE_REDIS:
    print("⚠️ Using in-memory storage (not persistent)")
    nonce_store = {}
    revoked_tokens = set()
    active_sessions = {}
else:
    nonce_store = {}
    revoked_tokens = set()
    active_sessions = {}

# ========== FASTAPI APP ==========
app = FastAPI(title="Auth Service")

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
AUTH0_DOMAIN = os.environ.get("AUTH0_DOMAIN", "apigatewaysecure.us.auth0.com")
AUTH0_CLIENT_ID = os.environ.get("AUTH0_CLIENT_ID", "5GkSY8Xk4oNRpJysIWx35UCyeInC0Vs3")
JWKS_URL = f"https://{AUTH0_DOMAIN}/.well-known/jwks.json"

# Secret nội bộ chỉ dùng giữa Gateway và Auth Service.
# Không đưa secret này vào frontend.
INTERNAL_AUTH_SECRET = os.environ.get(
    "INTERNAL_AUTH_SECRET",
    "dev-internal-auth-secret-change-me"
).encode()

NONCE_EXPIRY = 120
SESSION_EXPIRY = 86400

# ========== NONCE STORAGE ==========
def store_nonce(nonce: str):
    if USE_REDIS:
        redis_client.setex(f"auth_nonce:{nonce}", NONCE_EXPIRY, "1")
    else:
        nonce_store[nonce] = time.time()
        cleanup_nonces()


def is_nonce_used(nonce: str) -> bool:
    if USE_REDIS:
        return redis_client.get(f"auth_nonce:{nonce}") is not None
    cleanup_nonces()
    return nonce in nonce_store


def cleanup_nonces():
    if not USE_REDIS:
        now = time.time()
        expired = [n for n, t in nonce_store.items() if now - t > NONCE_EXPIRY]
        for n in expired:
            del nonce_store[n]

# ========== SESSION FUNCTIONS ==========
def get_active_session(user_id: str) -> Optional[str]:
    if USE_REDIS:
        return redis_client.get(f"active_session:{user_id}")
    return active_sessions.get(user_id)


def set_active_session(user_id: str, token_hash: str):
    if USE_REDIS:
        redis_client.setex(f"active_session:{user_id}", SESSION_EXPIRY, token_hash)
    else:
        active_sessions[user_id] = token_hash


def clear_active_session(user_id: str):
    if USE_REDIS:
        redis_client.delete(f"active_session:{user_id}")
    else:
        active_sessions.pop(user_id, None)

# ========== TOKEN REVOCATION ==========
def is_token_revoked(token_hash: str) -> bool:
    if USE_REDIS:
        return redis_client.sismember("revoked_tokens", token_hash)
    return token_hash in revoked_tokens


def revoke_token(token_hash: str):
    if USE_REDIS:
        redis_client.sadd("revoked_tokens", token_hash)
        redis_client.expire("revoked_tokens", SESSION_EXPIRY)
    else:
        revoked_tokens.add(token_hash)

# ========== JWT ==========
jwks_client = jwt.PyJWKClient(JWKS_URL)


def get_roles(payload: dict) -> list[str]:
    return payload.get("https://api-gateway-demo.com/roles", []) or payload.get("roles", []) or []


def verify_jwt(token: str, check_session: bool = True) -> dict:
    token_hash = hashlib.sha256(token.encode()).hexdigest()

    if is_token_revoked(token_hash):
        raise HTTPException(status_code=401, detail="Token revoked")

    signing_key = jwks_client.get_signing_key_from_jwt(token)
    payload = jwt.decode(
        token,
        signing_key.key,
        algorithms=["RS256"],
        audience=AUTH0_CLIENT_ID,
        issuer=f"https://{AUTH0_DOMAIN}/",
        options={"verify_exp": True},
    )

    if check_session:
        user_id = payload.get("sub")
        active_token_hash = get_active_session(user_id)

        if not active_token_hash:
            raise HTTPException(status_code=401, detail="No active session - please login")

        if active_token_hash != token_hash:
            raise HTTPException(status_code=401, detail="Token invalid - new session")

    return payload


def verify_internal_gateway_hmac(
    method: str,
    path: str,
    timestamp: str,
    nonce: str,
    signature: str,
    body: str,
) -> None:
    if not timestamp or not nonce or not signature:
        raise HTTPException(status_code=401, detail="Missing internal Gateway HMAC headers")

    try:
        ts = int(timestamp)
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid Gateway timestamp")

    now = int(datetime.now(timezone.utc).timestamp())
    if abs(now - ts) > 60:
        raise HTTPException(status_code=401, detail="Gateway timestamp expired")

    if is_nonce_used(nonce):
        raise HTTPException(status_code=401, detail="Gateway nonce already used")

    canonical = f"{method}|{path}|{timestamp}|{nonce}|{body}"
    expected = hmac.new(INTERNAL_AUTH_SECRET, canonical.encode(), hashlib.sha256).hexdigest()

    if not hmac.compare_digest(expected, signature):
        raise HTTPException(status_code=401, detail="Invalid internal Gateway HMAC signature")

    store_nonce(nonce)

# ========== API ENDPOINTS ==========
@app.api_route("/auth/verify", methods=["GET", "POST", "PUT", "DELETE"])
async def verify_endpoint(
    request: Request,
    authorization: str = Header(None),
    x_gateway_timestamp: str = Header(None),
    x_gateway_nonce: str = Header(None),
    x_gateway_signature: str = Header(None),
    x_required_role: str = Header(None),
):
    """Verify JWT/session/role and the Gateway's internal HMAC signature.

    This endpoint is intended to be called by API Gateway, not directly by frontend.
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    token = authorization.split(" ")[1]

    try:
        jwt_payload = verify_jwt(token, check_session=True)
    except ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except InvalidTokenError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")

    body_bytes = await request.body()
    body_str = body_bytes.decode() if body_bytes else ""
    original_method = request.headers.get("x-original-method", request.method)
    original_path = request.headers.get("x-original-path", request.url.path)

    verify_internal_gateway_hmac(
        method=original_method,
        path=original_path,
        timestamp=x_gateway_timestamp,
        nonce=x_gateway_nonce,
        signature=x_gateway_signature,
        body=body_str,
    )

    roles = get_roles(jwt_payload)
    if x_required_role:
        required_roles = [role.strip() for role in x_required_role.split(",") if role.strip()]
        if required_roles and not any(role in roles for role in required_roles):
            raise HTTPException(status_code=403, detail=f"Role required: {required_roles}")

    return {
        "verified": True,
        "jwt_verified": True,
        "hmac_verified": True,
        "session_active": True,
        "user": jwt_payload.get("sub"),
        "email": jwt_payload.get("email", jwt_payload.get("sub")),
        "roles": roles,
    }


@app.post("/auth/login")
async def login_endpoint(authorization: str = Header(None)):
    """Login after Auth0 callback.

    Frontend calls this once with Bearer id_token. Auth Service verifies Auth0 JWT
    and stores the active session. No HMAC is required here because login is the
    step that creates the session.
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    token = authorization.split(" ")[1]

    try:
        payload = verify_jwt(token, check_session=False)
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")

    user_id = payload.get("sub")
    token_hash = hashlib.sha256(token.encode()).hexdigest()

    clear_active_session(user_id)
    set_active_session(user_id, token_hash)

    return {
        "message": "Login successful",
        "user": user_id,
        "email": payload.get("email", user_id),
        "roles": get_roles(payload),
    }


@app.post("/auth/revoke")
async def revoke_token_endpoint(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    token = authorization.split(" ")[1]

    try:
        payload = verify_jwt(token)
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")

    token_hash = hashlib.sha256(token.encode()).hexdigest()
    revoke_token(token_hash)

    user_id = payload.get("sub")
    clear_active_session(user_id)

    return {
        "message": "Logged out successfully",
        "user": user_id,
        "revoked_at": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/auth/health")
async def health():
    return {
        "status": "ok",
        "service": "auth",
        "redis": USE_REDIS,
        "nonce_store_size": len(nonce_store) if not USE_REDIS else "redis",
    }


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)
