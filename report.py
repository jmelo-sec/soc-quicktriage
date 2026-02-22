from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from colorama import init

init(autoreset=True, convert=True)


def _c(text: str, color: str, enabled: bool) -> str:
    if not enabled:
        return text
    colors = {
        "red": "\033[91m",
        "yellow": "\033[93m",
        "green": "\033[92m",
        "cyan": "\033[96m",
        "reset": "\033[0m",
        "bold": "\033[1m",
    }
    return f"{colors.get(color,'')}{text}{colors['reset']}"


def build_report(
    ioc: str,
    ioc_type: str,
    results: Dict[str, Any],
    score: float,
    verdict: str,
    factors: Optional[List[str]] = None,
) -> Dict[str, Any]:
    return {
        "timestamp_utc": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "ioc": ioc,
        "ioc_type": ioc_type,
        "sources": results,
        "risk": {
            "score": score,
            "verdict": verdict,
            "factors": factors or [],
        },
    }


def print_human(report: Dict[str, Any], color: bool = True) -> None:
    risk = report["risk"]
    verdict = risk["verdict"]

    if verdict == "LOW":
        vtxt = _c(verdict, "green", color)
    elif verdict == "MEDIUM":
        vtxt = _c(verdict, "cyan", color)
    elif verdict == "HIGH":
        vtxt = _c(verdict, "yellow", color)
    else:
        vtxt = _c(verdict, "red", color)

    print("\n--- SOC QUICKTRIAGE REPORT ---")
    print(f"Time (UTC): {report['timestamp_utc']}")
    print(f"IOC       : {report['ioc']}")
    print(f"Type      : {report['ioc_type']}")
    print("\nSources:")

    sources = report.get("sources", {})
    if not sources:
        print(" - (no data)")
    else:
        for name, data in sources.items():
            if not isinstance(data, dict):
                print(f" - {name}: {data}")
                continue
            if "error" in data:
                print(f" - {name}: ERROR - {data.get('error')}")
                continue

            # Pretty per source
            if name == "virustotal":
                mal = data.get("malicious", 0)
                susp = data.get("suspicious", 0)
                print(f" - VirusTotal : malicious={mal} suspicious={susp}")
            elif name == "abuseipdb":
                conf = data.get("abuseConfidenceScore", 0)
                reps = data.get("totalReports", 0)
                cc = data.get("countryCode", "")
                print(f" - AbuseIPDB  : confidence={conf} reports={reps} country={cc}")
            elif name == "otx":
                pulses = data.get("pulse_count", 0)
                tags = ", ".join(data.get("tags", [])[:8])
                print(f" - OTX        : pulses={pulses} tags=[{tags}]")
            else:
                print(f" - {name}: {data}")

    print("\nRisk:")
    print(f" - Score   : {risk['score']}/100")
    print(f" - Verdict : {vtxt}")

    factors = risk.get("factors", [])
    if factors:
        print(" - Factors :")
        for f in factors:
            print(f"    - {f}")

    print("-----------------------------\n")