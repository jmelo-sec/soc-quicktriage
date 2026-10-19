# build_track3_alerts.py
# Construye el dataset de alertas (tabla 3, apartado 2.3.1) a partir de track3_dataset.csv 
# (IOCs y etiquetas) y track3_results.json (resultados del enriquecimiento con quicktriage.py).
#
# Diferencias con el Track 2:
#
# 1. Cada IOC conserva su risk_score y verdict del enriquecimiento. Los hashes no tienen IP 
#    de origen o destino; las IPs de C2 se guardan como dest_ip.
#
# 2. Las 5 IPs de C2 son distintas entre sí, así que el criterio de infraestructura no 
#    debería generar coincidencias entre estas alertas.
#
# 3. Los rule_id y rule_name se construyen a partir de family_or_source (track3_dataset.csv), 
#    de modo que no hace falta fijar una familia de malware en este script.

import csv
import json

DATASET_PATH = "track3_dataset.csv"
RESULTS_PATH = "track3_results.json"
OUTPUT_PATH = "track3_alerts.csv"

RULE_HASH = "MALWARE-HASH-DETECTION"
RULE_IP = "MALWARE-C2-COMMUNICATION"


def load_dataset(path):
    # Lee el CSV y detecta el delimitador automáticamente (',' o ';').
    rows = {}
    with open(path, encoding="utf-8-sig") as f:
        sample = f.read(2048)
        f.seek(0)
        dialect = csv.Sniffer().sniff(sample, delimiters=",;")
        reader = csv.DictReader(f, dialect=dialect)
        for row in reader:
            rows[row["ioc"]] = row
    return rows


def load_results(path):
    with open(path, encoding="utf-8") as f:
        results = json.load(f)
    return {result["ioc"]: result for result in results}


def main():
    dataset = load_dataset(DATASET_PATH)
    results = load_results(RESULTS_PATH)
    print(f"Se cargan {len(dataset)} IOCs desde {DATASET_PATH}")
    print(f"Se cargan {len(results)} resultados desde {RESULTS_PATH}")

    # Comprueba que el dataset contiene hashes e IPs.
    tipos = {row["ioc_type"] for row in dataset.values()}
    print(f"Tipos de IOC presentes: {tipos}")
    if "hash" not in tipos or "ip" not in tipos:
        print("Atención: Se esperaba una mezcla de hash + IP para este escenario, "
              "revisa el dataset antes de continuar.")

    alerts = []
    alert_id = 1

    for ioc, row in dataset.items():
        if ioc not in results:
            print(f"Atención: {ioc[:40]} no tiene resultado de Quicktriage, continuamos")
            continue

        result = results[ioc]
        risk = result["risk"]

        # Extrae el nombre de familia sin el sufijo entre paréntesis (p.ej. "RemcosRAT 
        # (MalwareBazaar, reutilizado del Track 1)" -> "RemcosRAT").
        family_label = row["family_or_source"].split(" (")[0].split(" C2")[0]

        # Los hashes no tienen IP asociada; las IPs de C2 van como destino.
        if row["ioc_type"] == "hash":
            source_ip = ""
            dest_ip = ""
            rule_id = RULE_HASH
            rule_name = f"{family_label} sample detection (MalwareBazaar)"
        else:  # ip
            source_ip = ""
            dest_ip = ioc
            rule_id = RULE_IP
            rule_name = f"{family_label} C2 communication (ThreatFox)"

        alerts.append({
            "alert_id": f"A{alert_id:04d}",
            "timestamp": row["first_seen"],
            "source_ip": source_ip,
            "dest_ip": dest_ip,
            "rule_id": rule_id,
            "rule_name": rule_name,
            "risk_score": risk["score"],
            "verdict": risk["verdict"],
        })
        alert_id += 1

    alerts.sort(key=lambda alert: alert["timestamp"])

    with open(OUTPUT_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "alert_id", "timestamp", "source_ip", "dest_ip",
            "rule_id", "rule_name", "risk_score", "verdict",
        ])
        writer.writeheader()
        writer.writerows(alerts)

    n_hash = sum(1 for alert in alerts if alert["rule_id"] == RULE_HASH)
    n_ip = sum(1 for alert in alerts if alert["rule_id"] == RULE_IP)

    print(f"\nDataset de Alertas generado en: {OUTPUT_PATH}")
    print(f"Total Alertas: {len(alerts)} ({n_hash} de hash, {n_ip} de IP de C2)")

    # Confirma que las IPs de C2 son todas distintas.
    ips_unicas = {alert["dest_ip"] for alert in alerts if alert["dest_ip"]}
    print(f"IPs de C2 distintas: {len(ips_unicas)} (todas diferentes entre sí "
          f"si este número coincide con {n_ip})")


if __name__ == "__main__":
    main()