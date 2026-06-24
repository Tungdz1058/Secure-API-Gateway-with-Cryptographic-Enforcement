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
    "transfer": os.environ.get("TRANSFER_SERVICE_URL", "https://bank-transfer.onrender.com"),
    "account": os.environ.get("ACCOUNT_SERVICE_URL", "https://bank-account.onrender.com"),
    "admin": os.environ.get("ADMIN_SERVICE_URL", "https://bank-admin.onrender.com")
}

print("Service Map:", SERVICE_MAP)

# ========== ROUTE ==========
@app.api_route("/api/{service}/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def gateway(request: Request, service: str, path: str):
    service_url = SERVICE_MAP.get(service)
    if not service_url:
        raise HTTPException(status_code=404, detail=f"Service {service} not found")
    
    # Forward request
    async with httpx.AsyncClient() as client:
        try:
            response = await client.request(
                method=request.method,
                url=f"{service_url}/{service}/{path}",
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
