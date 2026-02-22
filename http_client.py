import time
import random
import requests

def get_json(url: str, headers: dict | None = None, params: dict | None = None, timeout: int = 15, max_retries: int = 3) -> tuple[int, dict | None, str | None]:
    """
    Returns: (status_code, json_dict_or_none, error_text_or_none)
    Retries on 429/5xx with backoff.
    """
    headers = headers or {}
    params = params or {}

    for attempt in range(1, max_retries + 1):
        try:
            r = requests.get(url, headers=headers, params=params, timeout=timeout)

            # Rate limit / transient failures
            if r.status_code in (429, 500, 502, 503, 504):
                wait = min(2 ** attempt, 10) + random.random()
                # Respect Retry-After if present
                ra = r.headers.get("Retry-After")
                if ra and ra.isdigit():
                    wait = max(wait, int(ra))
                time.sleep(wait)
                continue

            if r.status_code == 200:
                return r.status_code, r.json(), None

            return r.status_code, None, r.text[:200]

        except requests.RequestException as e:
            if attempt == max_retries:
                return 0, None, str(e)
            time.sleep(min(2 ** attempt, 10) + random.random())

    return 0, None, "Unknown error"