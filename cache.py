# cache.py
# Caché en disco para no consumir cuota de las APIs al consultar el mismo IOC.
# Cada fuente lleva su propio TTL.

import json
import os
import time
import hashlib

CACHE_DIR = ".cache"

def _key(s: str) -> str:
    # Hasheamos el IOC para no usarlo directamente como nombre de fichero.
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:24]

def get_cached(namespace: str, ioc: str, ttl_seconds: int = 3600) -> dict | None:
    os.makedirs(CACHE_DIR, exist_ok=True)
    cache_path = os.path.join(CACHE_DIR, f"{namespace}_{_key(ioc)}.json")
    if not os.path.exists(cache_path):
        return None
    try:
        with open(cache_path, "r", encoding="utf-8") as f:
            cached_data = json.load(f)
        cached_at = cached_data.get("_cached_at", 0)
        if time.time() - cached_at > ttl_seconds:
            return None
        return cached_data.get("data")
    except Exception:
        # Si el fichero está corrupto o da cualquier problema, utilizamos la API.
        return None

def set_cached(namespace: str, ioc: str, data: dict) -> None:
    os.makedirs(CACHE_DIR, exist_ok=True)
    cache_path = os.path.join(CACHE_DIR, f"{namespace}_{_key(ioc)}.json")
    try:
        with open(cache_path, "w", encoding="utf-8") as f:
            json.dump({"_cached_at": time.time(), "data": data}, f, indent=2)
    except Exception:
        # Si no se puede escribir, seguimos sin API. No es crítico.
        pass