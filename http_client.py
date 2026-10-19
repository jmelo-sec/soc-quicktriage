# http_client.py
# Cliente HTTP común para las tres fuentes (VT, AbuseIPDB, OTX).
# Añade reintentos con backoff para no romper cuando la API da 429 o 5xx.

import time
import random
import requests

def get_json(url: str, headers: dict | None = None, params: dict | None = None, timeout: int = 15, max_retries: int = 3) -> tuple[int, dict | None, str | None]:
    # Devuelve status_code, json y error (si hay alguno). Si la API está saturada o falla, reintenta
    # varias veces esperando cada vez un poco más, hasta max_retries intentos.
    headers = headers or {}
    params = params or {}

    for attempt in range(1, max_retries + 1):
        try:
            response = requests.get(url, headers=headers, params=params, timeout=timeout)

            if response.status_code in (429, 500, 502, 503, 504):
                wait = min(2 ** attempt, 10) + random.random()
                # Si la API nos dice cuánto esperar antes de reintentar, le hacemos caso.
                retry_after = response.headers.get("Retry-After")
                if retry_after and retry_after.isdigit():
                    wait = max(wait, int(retry_after))
                time.sleep(wait)
                continue

            if response.status_code == 200:
                return response.status_code, response.json(), None

            return response.status_code, None, response.text[:200]

        except requests.RequestException as error:
            if attempt == max_retries:
                return 0, None, str(error)
            time.sleep(min(2 ** attempt, 10) + random.random())

    return 0, None, "Error desconocido"