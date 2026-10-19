# quicktriage.py
# Punto de entrada. Lee argumentos, lanza las consultas a las fuentes con caché de por
# medio y monta el informe final.

import argparse
import json
from dotenv import load_dotenv

from utils import detect_ioc_type
from enrich.virustotal import check_virustotal
from enrich.abuseipdb import check_abuseipdb
from enrich.otx import check_otx
from scoring import calculate_score, classify
from report import build_report, print_human
from cache import get_cached, set_cached

def triage_one(ioc: str) -> dict:
    ioc_type = detect_ioc_type(ioc)

    data = {}

    # VirusTotal (cache 6 horas)
    vt_cache = get_cached("vt", ioc, ttl_seconds=6*3600)
    if vt_cache:
        data["virustotal"] = vt_cache
    else:
        vt_result = check_virustotal(ioc, ioc_type)
        data["virustotal"] = vt_result
        set_cached("vt", ioc, vt_result)

    # AbuseIPDB solo tiene sentido para IPs (caché 6 horas)
    if ioc_type == "ip":
        abuse_cache = get_cached("abuse", ioc, ttl_seconds=6*3600)
        if abuse_cache:
            data["abuseipdb"] = abuse_cache
        else:
            abuse_result = check_abuseipdb(ioc)
            data["abuseipdb"] = abuse_result
            set_cached("abuse", ioc, abuse_result)

    # OTX (caché 6 horas)
    otx_cache = get_cached("otx", ioc, ttl_seconds=6*3600)
    if otx_cache:
        data["otx"] = otx_cache
    else:
        otx_result = check_otx(ioc, ioc_type)
        data["otx"] = otx_result
        set_cached("otx", ioc, otx_result)

    score, factors = calculate_score(
        data.get("virustotal"),
        data.get("abuseipdb"),
        data.get("otx")
    )
    verdict = classify(score)

    return build_report(ioc, ioc_type, data, score, verdict, factors)

def main():
    load_dotenv()

    parser = argparse.ArgumentParser(description="SOC QuickTriage - Enriquecimiento y Score de IOCs")
    parser.add_argument("--ioc", help="Un IOC (IP / dominio / hash)")
    parser.add_argument("--batch", help="Fichero con un IOC por linea")
    parser.add_argument("--json", dest="json_out", help="Guardar el informe en JSON")
    parser.add_argument("--quiet", action="store_true", help="No imprimir el output legible")

    # Opciones relacionadas con el formato y la presentación de salida
    parser.add_argument("--format", choices=["human", "json"], default="human", help="Formato de salida")
    parser.add_argument("--no-color", action="store_true", help="Sin colores ANSI")

    args = parser.parse_args()

    reports = []

    # Procesamos un IOC suelto o un fichero completo en batch. Ignoramos las líneas vacías y las que
    # empiezan por '#' (comentarios en los ficheros de IOCs).
    if args.ioc:
        reports.append(triage_one(args.ioc.strip()))
    elif args.batch:
        with open(args.batch, "r", encoding="utf-8") as f:
            for line in f:
                ioc = line.strip()
                if not ioc or ioc.startswith("#"):
                    continue
                reports.append(triage_one(ioc))
    else:
        parser.error("Falta --ioc o --batch")

    use_color = not args.no_color

    if args.format == "human" and not args.quiet:
        for report in reports:
            print_human(report, color=use_color)

    if args.format == "json" and not args.json_out:
        output = reports[0] if len(reports) == 1 else reports
        print(json.dumps(output, indent=2))

    if args.json_out:
        output = reports[0] if len(reports) == 1 else reports
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2)
        if args.format == "human" and not args.quiet:
            print(f"JSON guardado en: {args.json_out}")


if __name__ == "__main__":
    main()