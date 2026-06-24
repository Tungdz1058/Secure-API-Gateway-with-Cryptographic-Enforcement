import os
import time
import hashlib
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import jwt
import hmac
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
        print("Redis connected")
    except Exception as e:
        print(f"Redis not available: {e}")

if not USE_REDIS:
    print("Using in-memory storage (not persistent)")
    nonce_store = {}
    revoked_tokens = set()
    active_sessions = {}
    kms_store = {}

# ========== FASTAPI APP ==========
app = FastAPI(title="Auth Service")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "https://secure-api-gateway-with-cryptograph.vercel.app",
        "https://*.vercel.app"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ========== CONFIG ==========
AUTH0_DOMAIN = os.environ.get("AUTH0_DOMAIN", "apigatewaysecure.us.auth0.com")
AUTH0_CLIENT_ID = os.environ.get("AUTH0_CLIENT_ID", "5GkSY8Xk4oNRpJysIWx35UCyeInC0Vs3")
JWKS_URL = f"https://{AUTH0_DOMAIN}/.well-known/jwks.json"
HMAC_SECRET = os.environ.get("HMAC_SECRET", "my-secret-key-change-in-production").encode()
DEFAULT_KEY_ID = "hmac-v1"

# ========== SESSION FUNCTIONS ==========
def get_active_session(user_id: str) -> Optional[str]:
    if USE_REDIS:
        return redis_client.get(f"active_session:{user_id}")
    return active_sessions.get(user_id)

def set_active_session(user_id: str, token_hash: str):
    if USE_REDIS:
        redis_client.set(f"active_session:{user_id}", token_hash)
        redis_client.expire(f"active_session:{user_id}", 86400)
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
        redis_client.expire("revoked_tokens", 86400)
    else:
        revoked_tokens.add(token_hash)

# ========== KMS ==========
def get_kms_key(key_id: str) -> Optional[str]:
    if USE_REDIS:
        return redis_client.get(f"kms:{key_id}")
    return kms_store.get(key_id)

def set_kms_key(key_id: str, value: str):
    if USE_REDIS:
        redis_client.set(f"kms:{key_id}", value)
        redis_client.expire(f"kms:{key_id}", 86400)
    else:
        kms_store[key_id] = value

def get_hmac_secret() -> bytes:
    secret = get_kms_key(DEFAULT_KEY_ID)
    if secret:
        return secret.encode()
    return HMAC_SECRET

# ========== JWT ==========
jwks_client = jwt.PyJWKClient(JWKS_URL)

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
        options={"verify_exp": True}
    )

    if check_session:
        user_id = payload.get("sub")
        active_token_hash = get_active_session(user_id)

        if not active_token_hash:
            raise HTTPException(status_code=401, detail="No active session - please login")

        if active_token_hash != token_hash:
            raise HTTPException(status_code=401, detail="Token invalid - new session")

    return payload

# ========== API ENDPOINTS ==========
@app.api_route("/auth/verify", methods=["GET", "POST", "PUT", "DELETE"])
async def verify_endpoint(
    request: Request,
    authorization: str = Header(None),
    x_timestamp: str = Header(None),
    x_nonce: str = Header(None),
    x_signature: str = Header(None),
    x_required_role: str = Header(None),
):
    # ===== 1. JWT VERIFICATION =====
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    token = authorization.split(" ")[1]

    try:
        jwt_payload = verify_jwt(token)
    except ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except InvalidTokenError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")
    except HTTPException as e:
        raise e

    # ===== 2. HMAC VERIFICATION =====
    hmac_verified = False
    if x_timestamp and x_nonce and x_signature:
        try:
            ts = int(x_timestamp)
            now = int(datetime.now(timezone.utc).timestamp())
            if abs(now - ts) > 60:
                raise HTTPException(status_code=401, detail="Timestamp expired")
        except ValueError:
            raise HTTPException(status_code=401, detail="Invalid timestamp")

        if USE_REDIS:
            if redis_client.get(x_nonce):
                raise HTTPException(status_code=401, detail="Nonce already used")
            redis_client.set(x_nonce, "1", ex=120)
        else:
            if x_nonce in nonce_store:
                raise HTTPException(status_code=401, detail="Nonce already used")
            nonce_store[x_nonce] = True

        body_bytes = await request.body()
        body_str = body_bytes.decode() if body_bytes else ""
        
        # ✅ Lấy method và path từ Gateway
        original_method = request.headers.get("x-original-method", request.method)
        original_path = request.headers.get("x-original-path", request.url.path)
        
        print(f"✅ Using original method: {original_method}")
        print(f"✅ Using original path: {original_path}")
        
        canonical = f"{original_method}|{original_path}|{x_timestamp}|{x_nonce}|{body_str}"
        print(f"🔑 Canonical: {canonical}")
        
        hmac_secret = get_hmac_secret()
        expected = hmac.new(hmac_secret, canonical.encode(), hashlib.sha256).hexdigest()
        print(f"🔑 Expected: {expected}")
        
        if not hmac.compare_digest(expected, x_signature):
            print(f"❌ Received: {x_signature}")
            raise HTTPException(status_code=401, detail="Invalid HMAC signature")
        hmac_verified = True

    # ===== 3. ROLE VERIFICATION =====
    if x_required_role:
        roles = jwt_payload.get("https://api-gateway-demo.com/roles", [])
        if x_required_role not in roles:
            raise HTTPException(
                status_code=403,
                detail=f"Role required: {x_required_role}"
            )

    # ===== 4. RESPONSE =====
    return {
        "verified": True,
        "jwt_verified": True,
        "hmac_verified": hmac_verified,
        "user": jwt_payload.get("sub"),
        "email": jwt_payload.get("email", jwt_payload.get("sub")),
        "roles": jwt_payload.get("https://api-gateway-demo.com/roles", []),
        "session_active": True
    }

@app.post("/auth/login")
async def login_endpoint(authorization: str = Header(None)):
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
        "user": user_id
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
        "revoked_at": datetime.now(timezone.utc).isoformat()
    }

@app.get("/auth/health")
async def health():
    return {"status": "ok", "service": "auth"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)
