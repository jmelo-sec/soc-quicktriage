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

    results = {}

    # --- VirusTotal (cache 6h) ---
    cached_vt = get_cached("vt", ioc, ttl_seconds=6*3600)
    if cached_vt:
        results["virustotal"] = cached_vt
    else:
        vt = check_virustotal(ioc, ioc_type)
        results["virustotal"] = vt
        set_cached("vt", ioc, vt)

    # --- AbuseIPDB (solo IP) (cache 6h) ---
    if ioc_type == "ip":
        cached_abuse = get_cached("abuse", ioc, ttl_seconds=6*3600)
        if cached_abuse:
            results["abuseipdb"] = cached_abuse
        else:
            abuse = check_abuseipdb(ioc)
            results["abuseipdb"] = abuse
            set_cached("abuse", ioc, abuse)

    # --- OTX (cache 6h) ---
    cached_otx = get_cached("otx", ioc, ttl_seconds=6*3600)
    if cached_otx:
        results["otx"] = cached_otx
    else:
        otx = check_otx(ioc, ioc_type)
        results["otx"] = otx
        set_cached("otx", ioc, otx)

    score, factors = calculate_score(
        results.get("virustotal"),
        results.get("abuseipdb"),
        results.get("otx")
    )
    verdict = classify(score)

    return build_report(ioc, ioc_type, results, score, verdict, factors)

def main():
    load_dotenv()

    parser = argparse.ArgumentParser(description="SOC QuickTriage - IOC enrichment + scoring")
    parser.add_argument("--ioc", help="Single IOC (IP / domain / hash)")
    parser.add_argument("--batch", help="File with one IOC per line")
    parser.add_argument("--json", dest="json_out", help="Write JSON report to file")
    parser.add_argument("--quiet", action="store_true", help="Do not print human-readable output")

    # 28) --no-color y --format
    parser.add_argument("--format", choices=["human", "json"], default="human", help="Output format")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")

    args = parser.parse_args()

    reports = []

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
        parser.error("Provide --ioc or --batch")

    # --- Sustituye el bloque final por este ---
    use_color = not args.no_color

    if args.format == "human" and not args.quiet:
        for r in reports:
            print_human(r, color=use_color)

    if args.format == "json" and not args.json_out:
        out = reports[0] if len(reports) == 1 else reports
        print(json.dumps(out, indent=2))

    if args.json_out:
        out = reports[0] if len(reports) == 1 else reports
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2)
        if args.format == "human" and not args.quiet:
            print(f"JSON written to: {args.json_out}")


if __name__ == "__main__":
    main()