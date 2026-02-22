import os
from http_client import get_json

BASE_URL = "https://www.virustotal.com/api/v3"


def check_virustotal(ioc: str, ioc_type: str) -> dict:
    api_key = os.getenv("VT_API_KEY")
    if not api_key:
        return {"source": "virustotal", "error": "VT_API_KEY not set"}

    headers = {"x-apikey": api_key}

    if ioc_type == "ip":
        url = f"{BASE_URL}/ip_addresses/{ioc}"
    elif ioc_type == "domain":
        url = f"{BASE_URL}/domains/{ioc}"
    else:
        url = f"{BASE_URL}/files/{ioc}"

    status, data, err = get_json(url, headers=headers, max_retries=4)

    # ---- Fallback para hash usando search ----
    if (status == 404 or not data) and ioc_type == "hash":
        search_url = f"{BASE_URL}/search?query={ioc}"
        status2, data2, err2 = get_json(search_url, headers=headers, max_retries=2)

        if status2 == 200 and data2:
            items = data2.get("data", [])
            if items:
                data = {"data": items[0]}
                status = 200
                err = None
            else:
                status, data, err = status2, data2, err2
        else:
            status, data, err = status2, data2, err2

    if status != 200 or not data:
        return {
            "source": "virustotal",
            "error": f"VirusTotal HTTP {status}",
            "details": err or "",
        }

    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))

    return {
        "source": "virustotal",
        "malicious": malicious,
        "suspicious": suspicious,
        "raw_stats": stats,
    }