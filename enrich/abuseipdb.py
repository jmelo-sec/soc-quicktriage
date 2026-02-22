import os
from http_client import get_json

def check_abuseipdb(ip: str) -> dict:
    api_key = os.getenv("ABUSE_API_KEY")
    if not api_key:
        return {"error": "ABUSE_API_KEY not set"}

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}

    status, data, err = get_json(url, headers=headers, params=params, max_retries=4)

    if status != 200 or not data:
        return {"error": f"AbuseIPDB HTTP {status}", "details": err or ""}

    d = data.get("data", {})
    return {
        "source": "abuseipdb",
        "abuseConfidenceScore": int(d.get("abuseConfidenceScore", 0)),
        "totalReports": int(d.get("totalReports", 0)),
        "countryCode": d.get("countryCode", ""),
        "isp": d.get("isp", "")
    }