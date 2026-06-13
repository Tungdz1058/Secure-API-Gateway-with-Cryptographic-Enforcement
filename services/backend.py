from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import jwt
import redis
import hmac
import hashlib
import os
import requests
from datetime import datetime, timezone
from jwt.exceptions import InvalidTokenError, ExpiredSignatureError

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "https://*.vercel.app"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

AUTH0_DOMAIN = os.environ.get("AUTH0_DOMAIN", "apigatewaysecure.us.auth0.com")
AUTH0_CLIENT_ID = os.environ.get("AUTH0_CLIENT_ID", "5GkSY8Xk4oNRpJysIWx35UCyeInC0Vs3")
JWKS_URL = f"https://{AUTH0_DOMAIN}/.well-known/jwks.json"

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379")
try:
    redis_client = redis.from_url(REDIS_URL, decode_responses=True)
    redis_client.ping()
    USE_REDIS = True
    print("[OK] Redis connected")
except Exception as e:
    USE_REDIS = False
    nonce_store = {}
    print(f"[WARN] Redis not available: {e}")

HMAC_SECRET = os.environ.get("HMAC_SECRET", "my-secret-key-change-in-production").encode()
jwks_client = jwt.PyJWKClient(JWKS_URL)

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

@app.api_route("/api/public", methods=["GET", "POST", "PUT", "DELETE"])
async def public_endpoint(
    request: Request,
    authorization: str = Header(None),
    x_timestamp: str = Header(None),
    x_nonce: str = Header(None),
    x_signature: str = Header(None),
):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    token = authorization.split(" ")[1]
    
    try:
        jwt_payload = verify_jwt(token)
    except ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except InvalidTokenError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")
    
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
        
        import asyncio
        loop = asyncio.get_event_loop()
        body_bytes = request.body()
        body = loop.run_until_complete(body_bytes) if not body_bytes.done() else body_bytes.result()
        body_str = body.decode()
        canonical = f"{request.method}|{request.url.path}|{x_timestamp}|{x_nonce}|{body_str}"
        expected = hmac.new(HMAC_SECRET, canonical.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, x_signature):
            raise HTTPException(status_code=401, detail="Invalid HMAC signature")
        hmac_verified = True
    
    return {
        "message": "API called successfully",
        "jwt_verified": True,
        "hmac_verified": hmac_verified,
        "user": jwt_payload.get("sub"),
        "email": jwt_payload.get("email", jwt_payload.get("sub")),
    }

@app.get("/admin/health")
async def health():
    return {"status": "ok"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)
