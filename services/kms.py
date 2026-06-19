import os
import json
import time
import redis
from typing import Optional, Dict, Tuple

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

if __name__ == "__main__":
    kms = MockKMS()
    kms.create_key("hmac-v1", "my-secret-key-123")
    secret = kms.get_key("hmac-v1")
    print("Secret: " + str(secret))
    manager = KeyRotationManager(kms)
    manager.rotate_with_grace("hmac-v1", "my-new-secret-key-456")
    valid = manager.get_valid_secret("hmac-v1")
    print("Valid secret: " + str(valid))
    print("All keys: " + str(kms.list_keys()))
