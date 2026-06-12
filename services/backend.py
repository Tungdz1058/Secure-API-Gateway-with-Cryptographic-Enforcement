from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import jwt
import requests
import redis
import hmac
import hashlib
import os
from datetime import datetime, timezone
from jwt.exceptions import InvalidTokenError, ExpiredSignatureError

app = FastAPI()

# CORS - cho phép website gọi API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Redis connection
try:
    redis_client = redis.Redis(host='localhost', port=6379, decode_responses=True)
    redis_client.ping()
    USE_REDIS = True
    print("[OK] Redis connected")
except Exception as e:
    USE_REDIS = False
    print(f"[WARN] Redis not available: {e}")
    nonce_store = {}

# JWT config
JWKS_URL = "http://localhost:8080/realms/api-gateway-demo/protocol/openid-connect/certs"
ISSUER = "http://localhost:8080/realms/api-gateway-demo"
AUDIENCE = "account"
jwks_client = jwt.PyJWKClient(JWKS_URL)

HMAC_SECRET = os.environ.get("HMAC_SECRET", "my-secret-key-change-in-production").encode()

def verify_jwt(token: str) -> dict:
    signing_key = jwks_client.get_signing_key_from_jwt(token)
    payload = jwt.decode(
        token,
        signing_key.key,
        algorithms=["RS256", "RS384", "RS512", "ES256"],
        audience=AUDIENCE,
        issuer=ISSUER,
        options={"verify_exp": True}
    )
    return payload

@app.api_route("/api/public", methods=["GET", "POST", "PUT", "DELETE"])
async def public_endpoint(
    request: Request,
    authorization: str = Header(None),
    x_timestamp: str = Header(None),
    x_nonce: str = Header(None),
    x_signature: str = Header(None),
):
    # 1. JWT (bat buoc)
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    token = authorization.split(" ")[1]
    
    try:
        jwt_payload = verify_jwt(token)
    except ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except InvalidTokenError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")
    
    # 2. HMAC (neu co headers)
    hmac_verified = False
    if x_timestamp and x_nonce and x_signature:
        try:
            ts = int(x_timestamp)
            now = int(datetime.now(timezone.utc).timestamp())
            if abs(now - ts) > 60:
                raise HTTPException(status_code=401, detail="Timestamp expired")
        except ValueError:
            raise HTTPException(status_code=401, detail="Invalid timestamp format")
        
        if USE_REDIS:
            if redis_client.get(x_nonce):
                raise HTTPException(status_code=401, detail="Nonce already used")
            redis_client.set(x_nonce, "1", ex=120)
        else:
            if x_nonce in nonce_store:
                raise HTTPException(status_code=401, detail="Nonce already used")
            nonce_store[x_nonce] = True
        
        body = await request.body()
        body_str = body.decode()
        method = request.method
        path = request.url.path
        canonical = f"{method}|{path}|{x_timestamp}|{x_nonce}|{body_str}"
        expected = hmac.new(HMAC_SECRET, canonical.encode(), hashlib.sha256).hexdigest()
        
        if not hmac.compare_digest(expected, x_signature):
            raise HTTPException(status_code=401, detail="Invalid HMAC signature")
        hmac_verified = True
    
    return {
        "message": "API called successfully",
        "jwt_verified": True,
        "hmac_verified": hmac_verified,
        "user": jwt_payload.get("preferred_username"),
        "email": jwt_payload.get("email"),
    }

@app.get("/admin/health")
async def health():
    return {"status": "ok"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)
