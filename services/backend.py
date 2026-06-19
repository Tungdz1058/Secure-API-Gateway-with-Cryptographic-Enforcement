from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import jwt
import redis
import hmac
import hashlib
import os
import requests
import time
from datetime import datetime, timezone
from jwt.exceptions import InvalidTokenError, ExpiredSignatureError
from typing import Optional, Tuple

app = FastAPI()

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

AUTH0_DOMAIN = os.environ.get("AUTH0_DOMAIN", "apigatewaysecure.us.auth0.com")
AUTH0_CLIENT_ID = os.environ.get("AUTH0_CLIENT_ID", "5GkSY8Xk4oNRpJysIWx35UCyeInC0Vs3")
JWKS_URL = f"https://{AUTH0_DOMAIN}/.well-known/jwks.json"

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379")
try:
    redis_client = redis.from_url(REDIS_URL, decode_responses=True)
    redis_client.ping()
    USE_REDIS = True
    print("Redis connected")
except Exception as e:
    USE_REDIS = False
    nonce_store = {}
    print(f"Redis not available: {e}")

class MockKMS:
    def __init__(self, redis_url: Optional[str] = None):
        self.redis_client = None
        if redis_url:
            try:
                self.redis_client = redis.from_url(redis_url, decode_responses=True)
                self.redis_client.ping()
                print("KMS: Redis connected")
            except:
                print("KMS: Redis not available, using memory")
                self.redis_client = None
        self._keys = {}

    def _get_key(self, key_id: str) -> Optional[str]:
        if self.redis_client:
            return self.redis_client.get("kms:key:" + key_id)
        return self._keys.get(key_id)

    def _set_key(self, key_id: str, value: str, ttl: int = None):
        if self.redis_client:
            self.redis_client.set("kms:key:" + key_id, value)
            if ttl:
                self.redis_client.expire("kms:key:" + key_id, ttl)
        else:
            self._keys[key_id] = value

    def create_key(self, key_id: str, secret: str) -> str:
        self._set_key(key_id, secret)
        print("KMS: Key " + key_id + " created")
        return key_id

    def get_key(self, key_id: str) -> Optional[str]:
        secret = self._get_key(key_id)
        if secret:
            print("KMS: Key " + key_id + " retrieved")
        else:
            print("KMS: Key " + key_id + " not found")
        return secret

    def rotate_key(self, key_id: str, new_secret: str) -> Tuple[str, str]:
        old_secret = self._get_key(key_id)
        new_key_id = key_id + ":v2"
        self._set_key(new_key_id, new_secret)
        print("KMS: Key rotated " + key_id + " -> " + new_key_id)
        return old_secret, new_secret

    def list_keys(self) -> list:
        if self.redis_client:
            keys = self.redis_client.keys("kms:key:*")
            return [k.replace("kms:key:", "") for k in keys]
        return list(self._keys.keys())

class KeyRotationManager:
    def __init__(self, kms: MockKMS):
        self.kms = kms
        self.grace_period = 300
        self.old_keys = {}

    def rotate_with_grace(self, key_id: str, new_secret: str):
        old_secret = self.kms.get_key(key_id)
        if old_secret:
            self.old_keys[key_id] = (old_secret, time.time() + self.grace_period)
        new_key_id = key_id + ":v2"
        self.kms.create_key(new_key_id, new_secret)
        print("Rotation: Key " + key_id + " rotated, grace period " + str(self.grace_period) + "s")
        return new_key_id

    def get_valid_secret(self, key_id: str) -> Optional[str]:
        new_secret = self.kms.get_key(key_id + ":v2")
        if new_secret:
            return new_secret
        if key_id in self.old_keys:
            secret, expiry = self.old_keys[key_id]
            if time.time() < expiry:
                print("Rotation: Using old key " + key_id + " (grace period)")
                return secret
            else:
                del self.old_keys[key_id]
        return self.kms.get_key(key_id)

kms = MockKMS()
rotation_manager = KeyRotationManager(kms)

DEFAULT_KEY_ID = "hmac-v1"
if not kms.get_key(DEFAULT_KEY_ID):
    default_secret = os.environ.get("HMAC_SECRET", "my-secret-key-change-in-production")
    kms.create_key(DEFAULT_KEY_ID, default_secret)

def get_hmac_secret() -> bytes:
    secret = rotation_manager.get_valid_secret(DEFAULT_KEY_ID)
    if not secret:
        secret = os.environ.get("HMAC_SECRET", "my-secret-key-change-in-production")
    return secret.encode()

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

def verify_admin(token: str) -> bool:
    try:
        payload = verify_jwt(token)
        roles = payload.get("https://api-gateway-demo.com/roles", [])
        if "admin" in roles:
            return True
        return False
    except:
        return False

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

        body_bytes = await request.body()
        body_str = body_bytes.decode()
        canonical = f"{request.method}|{request.url.path}|{x_timestamp}|{x_nonce}|{body_str}"
        hmac_secret = get_hmac_secret()
        expected = hmac.new(hmac_secret, canonical.encode(), hashlib.sha256).hexdigest()
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

@app.get("/api/keys")
async def list_keys():
    return {"keys": kms.list_keys()}

@app.post("/api/rotate")
async def rotate_key(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    token = authorization.split(" ")[1]

    if not verify_admin(token):
        raise HTTPException(status_code=403, detail="Admin role required")

    new_secret = os.urandom(32).hex()
    rotation_manager.rotate_with_grace(DEFAULT_KEY_ID, new_secret)
    return {"message": "Key rotated", "new_key_id": f"{DEFAULT_KEY_ID}:v2"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)
