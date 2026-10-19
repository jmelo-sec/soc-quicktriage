# report.py
# Construye el informe final (JSON) y lo imprime por consola con colores.
# solo da formato a lo que ya viene calculado de scoring.py.

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from colorama import init

init(autoreset=True, convert=True)


def _c(text: str, color: str, enabled: bool) -> str:
    # Aplica color ANSI si está indicado; si no, devuelve el texto tal cual.
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
        "timestamp_utc": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
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

    # Color según severidad.
    if verdict == "LOW":
        vtxt = _c(verdict, "green", color)
    elif verdict == "MEDIUM":
        vtxt = _c(verdict, "cyan", color)
    elif verdict == "HIGH":
        vtxt = _c(verdict, "yellow", color)
    else:
        vtxt = _c(verdict, "red", color)

    print("\n--- SOC QuickTriage ---")
    print(f"Fecha: {report['timestamp_utc']}")
    print(f"IOC       : {report['ioc']} ({report['ioc_type']})")
    print("\nFuentes:")

    sources = report.get("sources", {})
    if not sources:
        print(" - (sin datos)")
    else:
        for source_name, source_data in sources.items():
            if not isinstance(source_data, dict):
                print(f" - {source_name}: {source_data}")
                continue
            if "error" in source_data:
                print(f" - {source_name}: ERROR - {source_data.get('error')}")
                continue

            # Cada fuente tiene su formato, así que van una a una.
            if source_name == "virustotal":
                malicious = source_data.get("malicious", 0)
                suspicious = source_data.get("suspicious", 0)
                print(f" - VirusTotal: {malicious} maliciosos / {suspicious} sospechosos")
            elif source_name == "abuseipdb":
                confidence = source_data.get("abuseConfidenceScore", 0)
                reports = source_data.get("totalReports", 0)
                country = source_data.get("countryCode", "")
                print(f" - AbuseIPDB  : confianza {confidence}, {reports} reportes, país {country}")
            elif source_name == "otx":
                pulses = source_data.get("pulse_count", 0)
                tags = ", ".join(source_data.get("tags", [])[:8])
                print(f" - OTX: {pulses} pulses, etiquetas: {tags}")
            else:
                print(f" - {source_name}: {source_data}")

    print(f"\nScore   : {risk['score']}/100")
    print(f"\nVeredicto : {vtxt}")

    factors = risk.get("factors", [])
    if factors:
        print("Factores:")
        for factor in factors:
            print(f"    - {factor}")

    print("-----------------------------\n")