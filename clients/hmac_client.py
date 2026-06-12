import requests
import time
import uuid
import hmac
import hashlib
import sys

# Địa chỉ API qua Kong (hoặc trực tiếp backend)
API_URL = "http://localhost:8000/api/public"
HMAC_SECRET = b"change-this-secret-in-production"  # phải giống với backend

def sign_request(method, url, body, timestamp, nonce):
    canonical = f"{method}|{url}|{timestamp}|{nonce}|{body}"
    return hmac.new(HMAC_SECRET, canonical.encode(), hashlib.sha256).hexdigest()

def call_api(jwt_token):
    method = "GET"
    url = API_URL
    body = ""
    timestamp = str(int(time.time()))
    nonce = str(uuid.uuid4())
    signature = sign_request(method, url, body, timestamp, nonce)
    
    headers = {
        "Authorization": f"Bearer {jwt_token}",
        "X-Timestamp": timestamp,
        "X-Nonce": nonce,
        "X-Signature": signature
    }
    response = requests.get(url, headers=headers)
    print(f"Status: {response.status_code}")
    print(f"Response: {response.json()}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python hmac_client.py <jwt_token>")
        sys.exit(1)
    jwt_token = sys.argv[1]
    call_api(jwt_token)
