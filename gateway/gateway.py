from fastapi import FastAPI, Request, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
import httpx
import jwt
import os
import hashlib
import redis
import hmac
from datetime import datetime, timezone
import sys
sys.path.append("..")
from services.shared.models import User

app = FastAPI(title="Bank API Gateway")

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

# Redis
REDIS_URL = os.environ.get("REDIS_URL", "")
try:
    if REDIS_URL:
        redis_client = redis.from_url(REDIS_URL, decode_responses=True)
        redis_client.ping()
        USE_REDIS = True
        print("Redis connected")
    else:
        USE_REDIS = False
        nonce_store = {}
        session_store = {}
        print("Redis not available: no URL")
except Exception as e:
    USE_REDIS = False
    nonce_store = {}
    session_store = {}
    print(f"Redis not available: {e}")

jwks_client = jwt.PyJWKClient(JWKS_URL)

# ========== SERVICE MAP ==========
SERVICE_MAP = {
    "transfer": os.environ.get("TRANSFER_SERVICE_URL", "https://bank-transfer.onrender.com"),
    "account": os.environ.get("ACCOUNT_SERVICE_URL", "https://bank-account.onrender.com"),
    "admin": os.environ.get("ADMIN_SERVICE_URL", "https://bank-admin.onrender.com")
}

ROLE_REQUIREMENTS = {
    "transfer": ["user", "admin"],
    "account": ["user", "admin"],
    "admin": ["admin"]
}

print("Service Map:", SERVICE_MAP)

# ========== AUTH FUNCTIONS ==========
def verify_jwt(token: str) -> dict:
    signing_key = jwks_client.get_signing_key_from_jwt(token)
    payload = jwt.decode(
        token,
        signing_key.key,
        algorithms=["RS256"],
        audience=AUTH0_CLIENT_ID,
        issuer=f"https://{AUTH0_DOMAIN}/",
        options={"verify_exp": True}
    )
    return payload

def get_active_session(user_id: str) -> str:
    if USE_REDIS:
        return redis_client.get(f"session:{user_id}")
    return session_store.get(user_id)

def set_active_session(user_id: str, token_hash: str):
    if USE_REDIS:
        redis_client.set(f"session:{user_id}", token_hash)
        redis_client.expire(f"session:{user_id}", 86400)
    else:
        session_store[user_id] = token_hash

def clear_active_session(user_id: str):
    if USE_REDIS:
        redis_client.delete(f"session:{user_id}")
    else:
        session_store.pop(user_id, None)

def check_replay(nonce: str) -> bool:
    if USE_REDIS:
        if redis_client.get(nonce):
            return False
        redis_client.set(nonce, "1", ex=120)
    else:
        if nonce in nonce_store:
            return False
        nonce_store[nonce] = True
    return True

def check_role(token: str, allowed_roles: list) -> bool:
    try:
        payload = verify_jwt(token)
        roles = payload.get("https://api-gateway-demo.com/roles", [])
        return any(r in allowed_roles for r in roles)
    except:
        return False

# ========== HMAC VERIFICATION ==========
async def verify_hmac(request: Request, timestamp: str, nonce: str, signature: str) -> bool:
    body = await request.body()
    body_str = body.decode() if body else ""
    canonical = f"{request.method}|{request.url.path}|{timestamp}|{nonce}|{body_str}"
    expected = hmac.new(HMAC_SECRET, canonical.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)

# ========== GATEWAY ROUTE ==========
@app.get("/")
async def root():
    return {"message": "Bank API Gateway is running", "status": "ok"}

@app.get("/health")
async def health():
    services_status = {}
    for name, url in SERVICE_MAP.items():
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(f"{url}/health", timeout=2)
                services_status[name] = "ok" if response.status_code == 200 else "error"
        except:
            services_status[name] = "unavailable"
    return {"status": "ok", "services": services_status}

@app.api_route("/api/{service}/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def gateway(
    request: Request,
    service: str,
    path: str,
    authorization: str = Header(None),
    x_timestamp: str = Header(None),
    x_nonce: str = Header(None),
    x_signature: str = Header(None)
):
    # ===== LỚP 1: Xác thực JWT =====
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    token = authorization.split(" ")[1]
    
    try:
        payload = verify_jwt(token)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")
    
    # Kiểm tra session
    user_id = payload.get("sub")
    active_session = get_active_session(user_id)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    if active_session and active_session != token_hash:
        raise HTTPException(status_code=401, detail="Token invalid - new session")
    
    # ===== LỚP 2: Role Check (RBAC) =====
    allowed_roles = ROLE_REQUIREMENTS.get(service, ["user"])
    if not check_role(token, allowed_roles):
        raise HTTPException(
            status_code=403,
            detail=f"Role required: {allowed_roles}"
        )
    
    # ===== LỚP 3: HMAC Verification =====
    if not x_timestamp or not x_nonce or not x_signature:
        raise HTTPException(status_code=401, detail="Missing HMAC headers")
    
    # Timestamp (60s)
    try:
        ts = int(x_timestamp)
        now = int(datetime.now(timezone.utc).timestamp())
        if abs(now - ts) > 60:
            raise HTTPException(status_code=401, detail="Timestamp expired")
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid timestamp")
    
    # Nonce
    if not check_replay(x_nonce):
        raise HTTPException(status_code=401, detail="Nonce already used")
    
    # HMAC
    if not await verify_hmac(request, x_timestamp, x_nonce, x_signature):
        raise HTTPException(status_code=401, detail="Invalid HMAC signature")
    
    # ===== LỚP 4: Route =====
    service_url = SERVICE_MAP.get(service)
    if not service_url:
        raise HTTPException(status_code=404, detail=f"Service {service} not found")
    
    # Forward request
    async with httpx.AsyncClient() as client:
        try:
            response = await client.request(
                method=request.method,
                url=f"{service_url}/{path}",
                headers={k: v for k, v in request.headers.items() if k != "host"},
                content=await request.body()
            )
            return response.json()
        except httpx.ConnectError:
            raise HTTPException(status_code=503, detail=f"Service {service} unavailable")

# ========== LOGIN / REVOKE ==========
@app.post("/api/login")
async def login(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    token = authorization.split(" ")[1]
    
    try:
        payload = verify_jwt(token)
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")
    
    user_id = payload.get("sub")
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    clear_active_session(user_id)
    set_active_session(user_id, token_hash)
    
    return {"message": "Login successful", "user": user_id}

@app.post("/api/revoke")
async def revoke(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    token = authorization.split(" ")[1]
    
    try:
        payload = verify_jwt(token)
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")
    
    user_id = payload.get("sub")
    clear_active_session(user_id)
    
    return {"message": "Logged out successfully", "user": user_id}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)
