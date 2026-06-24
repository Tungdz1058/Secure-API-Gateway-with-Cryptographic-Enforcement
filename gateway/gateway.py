from fastapi import FastAPI, Request, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
import httpx
import os
import hmac
import hashlib
import time
import asyncio
import logging

# ========== LOGGING ==========
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("gateway")

app = FastAPI(title="API Gateway")

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
HMAC_SECRET = os.environ.get("HMAC_SECRET", "my-secret-key-change-in-production").encode()
CACHE_TTL = 600
MAX_RETRIES = 3

# ========== SERVICE MAP ==========
SERVICE_MAP = {
    "auth": os.environ.get("AUTH_SERVICE_URL", "https://bank-auth.onrender.com"),
    "transfer": os.environ.get("TRANSFER_SERVICE_URL", "https://bank-transfer-vd1p.onrender.com"),
    "account": os.environ.get("ACCOUNT_SERVICE_URL", "https://bank-account-corr.onrender.com"),
    "admin": os.environ.get("ADMIN_SERVICE_URL", "https://bank-admin-ou0n.onrender.com")
}

ROLE_REQUIREMENTS = {
    "admin": ["admin"],
    "transfer": ["user", "admin"],
    "account": ["user", "admin"]
}

PREFIX_SERVICES = ["auth"]

# ========== CACHE ==========
role_cache = {}

def get_cached_roles(token: str) -> list:
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    if token_hash in role_cache:
        cache_entry = role_cache[token_hash]
        if time.time() < cache_entry["expiry"]:
            logger.info(f"✅ Cache hit for token {token_hash[:10]}...")
            return cache_entry["roles"]
        else:
            del role_cache[token_hash]
            logger.info(f"⏰ Cache expired for token {token_hash[:10]}...")
    return None

def set_cached_roles(token: str, roles: list, ttl: int = CACHE_TTL):
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    role_cache[token_hash] = {
        "roles": roles,
        "expiry": time.time() + ttl
    }
    logger.info(f"💾 Cached roles {roles} for token {token_hash[:10]}... (TTL: {ttl}s)")

def clear_cache():
    role_cache.clear()
    logger.info("🗑️ Cache cleared")

# ========== AUTH SERVICE CALL WITH RETRY ==========
async def call_auth_service_with_retry(auth_url: str, headers: dict, max_retries: int = MAX_RETRIES):
    async with httpx.AsyncClient() as client:
        for attempt in range(max_retries):
            try:
                logger.info(f"🔗 Calling Auth Service: {auth_url} (attempt {attempt + 1}/{max_retries})")
                response = await client.post(
                    auth_url,
                    headers=headers,
                    timeout=5.0
                )
                
                if response.status_code == 429:
                    wait_time = 2 ** attempt
                    logger.warning(f"⏳ Rate limited, waiting {wait_time}s...")
                    await asyncio.sleep(wait_time)
                    continue
                
                return response
                
            except httpx.TimeoutException:
                logger.error(f"❌ Auth Service timeout (attempt {attempt + 1})")
                if attempt == max_retries - 1:
                    raise HTTPException(status_code=504, detail="Auth Service timeout")
                await asyncio.sleep(1)
                
            except httpx.ConnectError:
                logger.error(f"❌ Auth Service unavailable (attempt {attempt + 1})")
                if attempt == max_retries - 1:
                    raise HTTPException(status_code=503, detail="Auth Service unavailable")
                await asyncio.sleep(2)
    
    return None

# ========== ROUTE ==========
@app.api_route("/api/{service}/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def gateway(request: Request, service: str, path: str):
    service_url = SERVICE_MAP.get(service)
    if not service_url:
        raise HTTPException(status_code=404, detail=f"Service {service} not found")
    
    logger.info(f"📨 Request: {request.method} /api/{service}/{path} from {request.client.host}")
    
    if service in ROLE_REQUIREMENTS:
        authorization = request.headers.get("authorization")
        if not authorization:
            raise HTTPException(status_code=401, detail="Missing Authorization header")
        
        token = authorization.split(" ")[1] if authorization.startswith("Bearer ") else None
        if not token:
            raise HTTPException(status_code=401, detail="Invalid Authorization header")
        
        required_roles = ROLE_REQUIREMENTS[service]
        logger.info(f"🔍 Required roles for {service}: {required_roles}")
        
        cached_roles = get_cached_roles(token)
        if cached_roles is not None:
            if any(role in cached_roles for role in required_roles):
                logger.info(f"✅ Cache hit: token has one of {required_roles}")
            else:
                logger.warning(f"❌ Cache: token roles {cached_roles} not in {required_roles}")
                raise HTTPException(status_code=403, detail=f"Role required: {required_roles}")
        else:
            x_timestamp = request.headers.get("x-timestamp", "")
            x_nonce = request.headers.get("x-nonce", "")
            x_signature = request.headers.get("x-signature", "")
            
            if not x_timestamp or not x_nonce or not x_signature:
                raise HTTPException(status_code=401, detail="Missing HMAC headers")
            
            method = request.method
            full_path = f"/api/{service}/{path}"
            body = await request.body()
            body_str = body.decode() if body else ""
            canonical = f"{method}|{full_path}|{x_timestamp}|{x_nonce}|{body_str}"
            expected = hmac.new(HMAC_SECRET, canonical.encode(), hashlib.sha256).hexdigest()
            
            if not hmac.compare_digest(expected, x_signature):
                logger.warning(f"❌ Invalid HMAC signature for {full_path}")
                raise HTTPException(status_code=401, detail="Invalid HMAC signature")
            
            auth_url = f"{SERVICE_MAP['auth']}/auth/verify"
            verify_response = await call_auth_service_with_retry(
                auth_url,
                headers={
                    "Authorization": authorization,
                    "Content-Type": "application/json"
                }
            )
            
            if verify_response is None:
                raise HTTPException(status_code=503, detail="Auth Service unavailable")
            
            if verify_response.status_code != 200:
                error_detail = verify_response.text if verify_response.text else "Authentication failed"
                logger.error(f"❌ Auth Service error: {verify_response.status_code} - {error_detail[:100]}")
                raise HTTPException(status_code=verify_response.status_code, detail=error_detail[:200])
            
            try:
                verify_data = verify_response.json()
                roles = verify_data.get("roles", [])
                logger.info(f"🔍 Roles from Auth Service: {roles}")
                
                set_cached_roles(token, roles, ttl=CACHE_TTL)
                
                if not any(role in roles for role in required_roles):
                    logger.warning(f"❌ Auth: roles {roles} not in {required_roles}")
                    raise HTTPException(status_code=403, detail=f"Role required: {required_roles}")
                
            except Exception as e:
                logger.error(f"❌ Auth Service response error: {str(e)}")
                raise HTTPException(status_code=502, detail="Auth Service returned invalid response")
    
    if service in PREFIX_SERVICES:
        forward_path = f"{service}/{path}"
    else:
        forward_path = path
    
    headers = dict(request.headers)
    headers.pop("host", None)
    
    async with httpx.AsyncClient() as client:
        try:
            logger.info(f"➡️ Forwarding to: {service_url}/{forward_path}")
            response = await client.request(
                method=request.method,
                url=f"{service_url}/{forward_path}",
                headers=headers,
                content=await request.body(),
                timeout=10.0
            )
            
            content_type = response.headers.get("content-type", "")
            if "application/json" in content_type:
                logger.info(f"✅ Response from {service}: {response.status_code}")
                return response.json()
            else:
                logger.warning(f"⚠️ Non-JSON response from {service}: {response.status_code}")
                return {"error": "Service returned non-JSON response", "status": response.status_code}
                
        except httpx.ConnectError:
            logger.error(f"❌ Service {service} unavailable")
            raise HTTPException(status_code=503, detail=f"Service {service} unavailable")
        except httpx.TimeoutException:
            logger.error(f"❌ Service {service} timeout")
            raise HTTPException(status_code=504, detail=f"Service {service} timeout")

# ========== HEALTH CHECK ==========
@app.get("/health")
async def health():
    return {"status": "ok", "services": list(SERVICE_MAP.keys()), "cache_size": len(role_cache)}

# ========== CLEAR CACHE (Admin only) ==========
@app.post("/api/cache/clear")
async def clear_cache_endpoint(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    
    token = authorization.split(" ")[1]
    
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                f"{SERVICE_MAP['auth']}/auth/verify",
                headers={
                    "Authorization": authorization,
                    "Content-Type": "application/json"
                },
                timeout=5.0
            )
            if response.status_code != 200:
                raise HTTPException(status_code=403, detail="Admin required")
            verify_data = response.json()
            roles = verify_data.get("roles", [])
            if "admin" not in roles:
                raise HTTPException(status_code=403, detail="Admin required")
        except:
            raise HTTPException(status_code=503, detail="Auth Service unavailable")
    
    clear_cache()
    return {"message": "Cache cleared", "cache_size": 0}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
