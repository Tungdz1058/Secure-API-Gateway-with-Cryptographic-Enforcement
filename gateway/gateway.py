from fastapi import FastAPI, Request, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
import httpx
import os
import hashlib
import time
import asyncio
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
        "https://*.vercel.app"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ========== CONFIG ==========
CACHE_TTL = 600
MAX_RETRIES = 3

# ========== SERVICE MAP ==========
SERVICE_MAP = {
    "auth": os.environ.get("AUTH_SERVICE_URL", "https://bank-auth.onrender.com"),
    "transfer": os.environ.get("TRANSFER_SERVICE_URL", "https://bank-transfer-vd1p.onrender.com"),
    "account": os.environ.get("ACCOUNT_SERVICE_URL", "https://bank-account-corr.onrender.com"),
    "admin": os.environ.get("ADMIN_SERVICE_URL", "https://bank-admin-ou0n.onrender.com")
}

# ========== ROLE REQUIREMENTS ==========
ROLE_REQUIREMENTS = {
    "admin": ["admin"],
    "transfer": ["user", "admin"],
    "account": ["user", "admin"]
}

PREFIX_SERVICES = ["auth"]

# ========== CACHE ==========
role_cache = {}

def get_cached_roles(token: str):
    """Returns (roles, hmac_verified, jwt_verified, session_active) or (None, None, None, None)"""
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    if token_hash in role_cache:
        cache_entry = role_cache[token_hash]
        if time.time() < cache_entry["expiry"]:
            return (
                cache_entry.get("roles", []),
                cache_entry.get("hmac_verified", False),
                cache_entry.get("jwt_verified", False),
                cache_entry.get("session_active", False)
            )
        else:
            del role_cache[token_hash]
    return None, None, None, None

def set_cached_roles(token: str, roles: list, hmac_verified: bool = True, jwt_verified: bool = True, session_active: bool = True, ttl: int = CACHE_TTL):
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    role_cache[token_hash] = {
        "roles": roles,
        "hmac_verified": hmac_verified,
        "jwt_verified": jwt_verified,
        "session_active": session_active,
        "expiry": time.time() + ttl
    }

# ========== AUTH SERVICE CALL ==========
async def call_auth_service_with_retry(auth_url: str, headers: dict, body: str = "", max_retries: int = MAX_RETRIES):
    async with httpx.AsyncClient() as client:
        for attempt in range(max_retries):
            try:
                response = await client.post(
                    auth_url,
                    headers=headers,
                    content=body,
                    timeout=5.0
                )
                if response.status_code == 429:
                    await asyncio.sleep(2 ** attempt)
                    continue
                return response
            except httpx.TimeoutException:
                if attempt == max_retries - 1:
                    raise HTTPException(status_code=504, detail="Auth Service timeout")
                await asyncio.sleep(1)
            except httpx.ConnectError:
                if attempt == max_retries - 1:
                    raise HTTPException(status_code=503, detail="Auth Service unavailable")
                await asyncio.sleep(2)
    return None

# ========== MAIN ROUTE ==========
@app.api_route("/api/{service}/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def gateway(request: Request, service: str, path: str):
    service_url = SERVICE_MAP.get(service)
    if not service_url:
        raise HTTPException(status_code=404, detail=f"Service {service} not found")
    
    logger.info(f"📨 Request: {request.method} /api/{service}/{path}")
    
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
        
        # ===== CHECK CACHE =====
        cached_roles, cached_hmac, cached_jwt, cached_session = get_cached_roles(token)
        if cached_roles is not None:
            logger.info(f"✅ Cache hit for token")
            
            # Kiểm tra tất cả điều kiện từ cache
            if not cached_jwt:
                raise HTTPException(status_code=401, detail="JWT verification failed")
            if not cached_hmac:
                raise HTTPException(status_code=401, detail="Invalid HMAC signature")
            if not cached_session:
                raise HTTPException(status_code=401, detail="Session not active - please login")
            if not any(role in cached_roles for role in required_roles):
                raise HTTPException(status_code=403, detail=f"Role required: {required_roles}")
            
            # Cache valid, skip auth verification
            logger.info(f"✅ Cache valid, skipping auth verification")
        else:
            # ===== CALL AUTH SERVICE =====
            x_timestamp = request.headers.get("x-timestamp", "")
            x_nonce = request.headers.get("x-nonce", "")
            x_signature = request.headers.get("x-signature", "")

            if service in ROLE_REQUIREMENTS:
                if not x_timestamp or not x_nonce or not x_signature:
                    raise HTTPException(status_code=401, detail="Missing HMAC headers")
            
            body_bytes = await request.body()
            body_str = body_bytes.decode() if body_bytes else ""
            
            method = request.method
            
            auth_headers = {
                "Authorization": authorization,
                "Content-Type": "application/json",
                "X-Required-Role": required_role,
                "X-Timestamp": x_timestamp,
                "X-Nonce": x_nonce,
                "X-Signature": x_signature,
                "X-Original-Path": f"/api/{service}/{path}",
                "X-Original-Method": method
            }
            
            logger.info(f"🔑 Sending to Auth Service for verification")
            
            auth_url = f"{SERVICE_MAP['auth']}/auth/verify"
            verify_response = await call_auth_service_with_retry(auth_url, auth_headers, body_str)
            
            if verify_response is None or verify_response.status_code != 200:
                error_detail = "Authentication failed"
                if verify_response:
                    try:
                        error_detail = verify_response.json().get("detail", "Authentication failed")
                    except:
                        error_detail = verify_response.text[:100]
                raise HTTPException(status_code=403, detail=error_detail)
            
            verify_data = verify_response.json()
            logger.info(f"✅ Auth response: {verify_data}")
            
            # ===== EXTRACT AND VALIDATE =====
            hmac_verified = verify_data.get("hmac_verified", False)
            jwt_verified = verify_data.get("jwt_verified", False)
            session_active = verify_data.get("session_active", False)
            roles = verify_data.get("roles", [])
            
            # Lưu vào cache
            set_cached_roles(token, roles, hmac_verified, jwt_verified, session_active)
            
            # Kiểm tra tất cả điều kiện
            if not jwt_verified:
                raise HTTPException(status_code=401, detail="JWT verification failed")
            if not hmac_verified:
                logger.warning(f"❌ HMAC verification failed for request: {request.method} /api/{service}/{path}")
                raise HTTPException(status_code=401, detail="Invalid HMAC signature")
            if not session_active:
                raise HTTPException(status_code=401, detail="Session not active - please login")
            if not any(role in roles for role in required_roles):
                raise HTTPException(status_code=403, detail=f"Role required: {required_roles}")
            
            logger.info(f"✅ All verifications passed")
    
    # ===== FORWARD REQUEST =====
    if service in PREFIX_SERVICES:
        forward_path = f"{service}/{path}"
    else:
        forward_path = path
    
    headers = dict(request.headers)
    headers.pop("host", None)
    
    async with httpx.AsyncClient() as client:
        try:
            response = await client.request(
                method=request.method,
                url=f"{service_url}/{forward_path}",
                headers=headers,
                content=await request.body(),
                timeout=10.0
            )
            
            try:
                return response.json()
            except:
                return {"error": "Service error", "status": response.status_code}
        except httpx.ConnectError:
            raise HTTPException(status_code=503, detail=f"Service {service} unavailable")

# ========== HEALTH CHECK ==========
@app.get("/health")
async def health():
    return {
        "status": "ok",
        "services": list(SERVICE_MAP.keys()),
        "cache_size": len(role_cache)
    }

@app.get("/cache/stats")
async def cache_stats():
    """Debug endpoint to view cache statistics"""
    return {
        "cache_size": len(role_cache),
        "cache_entries": [
            {
                "token_hash": k,
                "roles": v.get("roles", []),
                "hmac_verified": v.get("hmac_verified", False),
                "expiry": v.get("expiry", 0)
            }
            for k, v in list(role_cache.items())[:10]  # Show first 10 entries
        ]
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
