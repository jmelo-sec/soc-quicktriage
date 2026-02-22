import os
from http_client import get_json

BASE_URL = "https://otx.alienvault.com/api/v1/indicators"

def check_otx(ioc: str, ioc_type: str) -> dict:
    api_key = os.getenv("OTX_API_KEY")
    if not api_key:
        return {"error": "OTX_API_KEY not set"}

    headers = {"X-OTX-API-KEY": api_key}

    if ioc_type == "ip":
        url = f"{BASE_URL}/IPv4/{ioc}/general"
    elif ioc_type == "domain":
        url = f"{BASE_URL}/domain/{ioc}/general"
    else:
        url = f"{BASE_URL}/file/{ioc}/general"

    status, data, err = get_json(url, headers=headers, max_retries=4)

    if status != 200 or not data:
        return {"error": f"OTX HTTP {status}", "details": err or ""}

    pulse_info = data.get("pulse_info", {})
    pulses = pulse_info.get("pulses", []) or []

    tags = []
    for p in pulses[:10]:
        tags.extend(p.get("tags", []) or [])
    tags = list(dict.fromkeys([t for t in tags if t]))

    return {"source": "otx", "pulse_count": len(pulses), "tags": tags[:20]}