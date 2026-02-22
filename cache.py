import json
import os
import time
import hashlib

CACHE_DIR = ".cache"

def _key(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:24]

def get_cached(namespace: str, ioc: str, ttl_seconds: int = 3600) -> dict | None:
    os.makedirs(CACHE_DIR, exist_ok=True)
    path = os.path.join(CACHE_DIR, f"{namespace}_{_key(ioc)}.json")
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            obj = json.load(f)
        ts = obj.get("_cached_at", 0)
        if time.time() - ts > ttl_seconds:
            return None
        return obj.get("data")
    except Exception:
        return None

def set_cached(namespace: str, ioc: str, data: dict) -> None:
    os.makedirs(CACHE_DIR, exist_ok=True)
    path = os.path.join(CACHE_DIR, f"{namespace}_{_key(ioc)}.json")
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"_cached_at": time.time(), "data": data}, f, indent=2)
    except Exception:
        pass