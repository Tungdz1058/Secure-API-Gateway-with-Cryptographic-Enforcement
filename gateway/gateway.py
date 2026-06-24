from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import httpx
import os

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

# ========== SERVICE MAP ==========
SERVICE_MAP = {
    "auth": os.environ.get("AUTH_SERVICE_URL", "https://bank-auth.onrender.com"),
    "transfer": os.environ.get("TRANSFER_SERVICE_URL", "https://bank-transfer-vd1p.onrender.com"),
    "account": os.environ.get("ACCOUNT_SERVICE_URL", "https://bank-account-corr.onrender.com"),
    "admin": os.environ.get("ADMIN_SERVICE_URL", "https://bank-admin-ou0n.onrender.com")
}

# ========== ROLE REQUIREMENTS ==========
ROLE_REQUIREMENTS = {
    "admin": ["admin"],  # Chỉ admin mới vào /api/admin/*
    "transfer": ["user", "admin"],
    "account": ["user", "admin"]
}

PREFIX_SERVICES = ["auth"]

print("Service Map:", SERVICE_MAP)

# ========== ROUTE ==========
@app.api_route("/api/{service}/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def gateway(request: Request, service: str, path: str):
    service_url = SERVICE_MAP.get(service)
    if not service_url:
        raise HTTPException(status_code=404, detail=f"Service {service} not found")
    
    # ===== KIỂM TRA ROLE QUA AUTH SERVICE =====
    if service in ROLE_REQUIREMENTS:
        authorization = request.headers.get("authorization")
        if not authorization:
            raise HTTPException(status_code=401, detail="Missing Authorization header")
        
        # Lấy các header HMAC
        x_timestamp = request.headers.get("x-timestamp", "")
        x_nonce = request.headers.get("x-nonce", "")
        x_signature = request.headers.get("x-signature", "")
        required_role = ROLE_REQUIREMENTS[service][0]
        
        # Gọi Auth Service để verify
        async with httpx.AsyncClient() as client:
            try:
                verify_response = await client.post(
                    f"{SERVICE_MAP['auth']}/auth/verify",
                    headers={
                        "Authorization": authorization,
                        "X-Timestamp": x_timestamp,
                        "X-Nonce": x_nonce,
                        "X-Signature": x_signature,
                        "X-Required-Role": required_role,
                        "Content-Type": "application/json"
                    }
                )
                
                if verify_response.status_code != 200:
                    raise HTTPException(
                        status_code=verify_response.status_code,
                        detail=verify_response.json().get("detail", "Authentication failed")
                    )
            except httpx.ConnectError:
                raise HTTPException(status_code=503, detail="Auth Service unavailable")
    
    # ===== FORWARD REQUEST =====
    if service in PREFIX_SERVICES:
        forward_path = f"{service}/{path}"
    else:
        forward_path = path
    
    async with httpx.AsyncClient() as client:
        try:
            response = await client.request(
                method=request.method,
                url=f"{service_url}/{forward_path}",
                headers={k: v for k, v in request.headers.items() if k != "host"},
                content=await request.body()
            )
            return response.json()
        except httpx.ConnectError:
            raise HTTPException(status_code=503, detail=f"Service {service} unavailable")

@app.get("/health")
async def health():
    return {"status": "ok", "services": list(SERVICE_MAP.keys())}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
