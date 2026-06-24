from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import httpx
import os
import hmac
import hashlib
import time
import asyncio

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

# ========== SERVICE MAP ==========
SERVICE_MAP = {
    "auth": "https://bank-auth.onrender.com",
    "transfer": "https://bank-transfer-vd1p.onrender.com",
    "account": "https://bank-account-corr.onrender.com",
    "admin": "https://bank-admin-ou0n.onrender.com"
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

def get_cached_roles(token: str) -> list:
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    if token_hash in role_cache:
        cache_entry = role_cache[token_hash]
        if time.time() < cache_entry["expiry"]:
            return cache_entry["roles"]
        else:
            del role_cache[token_hash]
    return None

def set_cached_roles(token: str, roles: list, ttl: int = 600):
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    role_cache[token_hash] = {
        "roles": roles,
        "expiry": time.time() + ttl
    }

print("Service Map:", SERVICE_MAP)

# ========== ROUTE ==========
@app.api_route("/api/{service}/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def gateway(request: Request, service: str, path: str):
    service_url = SERVICE_MAP.get(service)
    if not service_url:
        raise HTTPException(status_code=404, detail=f"Service {service} not found")
    
    # ===== KIỂM TRA ROLE =====
    if service in ROLE_REQUIREMENTS:
        authorization = request.headers.get("authorization")
        if not authorization:
            raise HTTPException(status_code=401, detail="Missing Authorization header")
        
        token = authorization.split(" ")[1] if authorization.startswith("Bearer ") else None
        if not token:
            raise HTTPException(status_code=401, detail="Invalid Authorization header")
        
        required_roles = ROLE_REQUIREMENTS[service]
        print(f"🔍 Required roles for {service}: {required_roles}")
        
        # Kiểm tra cache
        cached_roles = get_cached_roles(token)
        if cached_roles is not None:
            print(f"🔍 Cached roles: {cached_roles}")
            if any(role in cached_roles for role in required_roles):
                print(f"✅ Cache hit: token has one of {required_roles}")
            else:
                print(f"❌ Cache miss: token roles {cached_roles} not in {required_roles}")
                raise HTTPException(status_code=403, detail=f"Role required: {required_roles}")
        else:
            # Verify HMAC
            x_timestamp = request.headers.get("x-timestamp", "")
            x_nonce = request.headers.get("x-nonce", "")
            x_signature = request.headers.get("x-signature", "")
            
            method = request.method
            full_path = f"/api/{service}/{path}"
            body = await request.body()
            body_str = body.decode() if body else ""
            canonical = f"{method}|{full_path}|{x_timestamp}|{x_nonce}|{body_str}"
            expected = hmac.new(HMAC_SECRET, canonical.encode(), hashlib.sha256).hexdigest()
            
            if not hmac.compare_digest(expected, x_signature):
                raise HTTPException(status_code=401, detail="Invalid HMAC signature")
            
            # Gọi Auth Service
            async with httpx.AsyncClient() as client:
                try:
                    auth_url = f"{SERVICE_MAP['auth']}/auth/verify"
                    print(f"🔗 Calling Auth Service: {auth_url}")
                    
                    verify_response = await client.post(
                        auth_url,
                        headers={
                            "Authorization": authorization,
                            "Content-Type": "application/json"
                        },
                        timeout=5.0
                    )
                    
                    if verify_response.status_code == 429:
                        print("⏳ Rate limited, waiting 3s...")
                        await asyncio.sleep(3)
                        verify_response = await client.post(
                            auth_url,
                            headers={
                                "Authorization": authorization,
                                "Content-Type": "application/json"
                            },
                            timeout=5.0
                        )
                    
                    if verify_response.status_code != 200:
                        error_detail = verify_response.text if verify_response.text else "Authentication failed"
                        raise HTTPException(status_code=verify_response.status_code, detail=error_detail[:200])
                    
                    verify_data = verify_response.json()
                    roles = verify_data.get("roles", [])
                    print(f"🔍 Roles from Auth Service: {roles}")
                    
                    # Cache roles
                    set_cached_roles(token, roles, ttl=600)
                    
                    if not any(role in roles for role in required_roles):
                        print(f"❌ Auth Service: roles {roles} not in {required_roles}")
                        raise HTTPException(status_code=403, detail=f"Role required: {required_roles}")
                    
                except httpx.ConnectError:
                    raise HTTPException(status_code=503, detail="Auth Service unavailable")
                except httpx.TimeoutException:
                    raise HTTPException(status_code=504, detail="Auth Service timeout")
    
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
                content=await request.body()
            )
            
            content_type = response.headers.get("content-type", "")
            if "application/json" in content_type:
                return response.json()
            else:
                return {"error": "Service returned non-JSON response", "status": response.status_code}
                
        except httpx.ConnectError:
            raise HTTPException(status_code=503, detail=f"Service {service} unavailable")

@app.get("/health")
async def health():
    return {"status": "ok", "services": list(SERVICE_MAP.keys())}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
