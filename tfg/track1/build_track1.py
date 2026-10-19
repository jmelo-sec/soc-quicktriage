# build_track1.py
# Genera el CSV del track 1: hashes maliciosos reales de MalwareBazaar y elementos benignos
# (dominios e IPs de referencia). Salida: track1_dataset.csv
#
# Consulta los hashes directamente a la API de MalwareBazaar (query
# "get_recent"). La ejecución del script deja constancia de la consulta realizada.
#
# La API requiere una Auth-Key gratuita, registrada en auth.abuse.ch.
# Documentación: bazaar.abuse.ch/api/
#
# Solo aceptamos muestras con "signature" (familia identificada), necesaria
# para las consultas posteriores a OTX. He limitado también el número de muestras
# por familia (MAX_PER_FAMILY), para que el dataset no pierda diversidad.
#
# La columna ioc del CSV se extrae también a iocs_track1.txt, con un IOC por línea en UTF-8 sin BOM, 
# para el módulo de enriquecimiento. Ambos ficheros se generan a la vez para evitar que se desincronicen.

import sys
import csv
import json
import requests
from collections import Counter

MALWAREBAZAAR_API_URL = "https://mb-api.abuse.ch/api/v1/"
TARGET_MALICIOUS = 25
MAX_PER_FAMILY = 5
RECENT_SELECTOR = "100"  # últimas 100 muestras subidas a MalwareBazaar

RAW_EVIDENCE_PATH = "track1_malwarebazaar_raw.json"
OUTPUT_PATH = "track1_dataset.csv"
IOCS_TXT_PATH = "iocs_track1.txt"


def query_malwarebazaar_recent(auth_key, selector=RECENT_SELECTOR):
    # POST con query=get_recent y un selector temporal.
    headers = {"Auth-Key": auth_key}
    data = {"query": "get_recent", "selector": selector}
    response = requests.post(MALWAREBAZAAR_API_URL, headers=headers, data=data, timeout=30)
    response.raise_for_status()
    payload = response.json()

    if payload.get("query_status") != "ok":
        print(f"Atención: MalwareBazaar devuelve query_status={payload.get('query_status')}")
        return []

    return payload.get("data", [])

def select_diverse_samples(raw_samples, target, max_per_family):
    # Filtra por signature y limita el número de muestras por familia para evitar que el dataset 
    # quede dominado por una sola.
    selected = []
    family_counts = Counter()

    for sample in raw_samples:
        if len(selected) >= target:
            break
        signature = sample.get("signature")
        if not signature:
            continue
        if family_counts[signature] >= max_per_family:
            continue
        selected.append(sample)
        family_counts[signature] += 1

    return selected

def main():
    if len(sys.argv) != 2:
        print("Uso: python build_track1.py <TU_AUTH_KEY_DE_MALWAREBAZAAR>")
        sys.exit(1)

    auth_key = sys.argv[1]

    # 1) Hashes maliciosos. Extraídos automáticamente vía la API de MalwareBazaar
    #    (query "get_recent"), filtrando solo muestras con "signature" para tener
    #    familia de malware asociada, que luego nos sirve para OTX.
    print("Consultando MalwareBazaar: últimas muestras subidas")
    raw_samples = query_malwarebazaar_recent(auth_key)
    print(f"Muestras recibidas: {len(raw_samples)}")

    selected = select_diverse_samples(raw_samples, TARGET_MALICIOUS, MAX_PER_FAMILY)
    print(f"Muestras seleccionadas tras filtrar por signature y limitar a "
          f"{MAX_PER_FAMILY} por familia: {len(selected)}")

    if len(selected) < TARGET_MALICIOUS:
        print(f"Atención: solo se han encontrado {len(selected)} muestras válidas, "
              f"menos de las {TARGET_MALICIOUS} buscadas. Continúo con las que hay.")

    # Se guarda la respuesta de la API tal cual, como evidencia de procedencia.
    with open(RAW_EVIDENCE_PATH, "w", encoding="utf-8") as f:
        json.dump(selected, f, indent=2)
    print(f"Evidencia de procedencia (respuesta en crudo de la API) guardada en: {RAW_EVIDENCE_PATH}")

    families = Counter(sample["signature"] for sample in selected)
    print("Familias seleccionadas:")
    for family, count in families.most_common():
        print(f"  {family:<15} {count}")

    malicious_hashes = [
        (sample["sha256_hash"], sample["signature"], sample["first_seen"])
        for sample in selected
    ]

    # Benignos: Dominios de referencia de rankings tipo Tranco o Cloudflare Radar, además de 
    # resolutores DNS públicos conocidos.
    benign_domains = [
        "google.com", "youtube.com", "facebook.com", "instagram.com", "wikipedia.org",
        "amazon.com", "twitter.com", "x.com", "linkedin.com", "microsoft.com",
        "apple.com", "netflix.com", "reddit.com", "yahoo.com", "whatsapp.com",
        "office.com", "tiktok.com", "cloudflare.com", "github.com", "stackoverflow.com",
        "wordpress.org", "adobe.com", "zoom.us", "spotify.com", "paypal.com",
    ]

    benign_ips = [
        ("8.8.8.8", "Google Public DNS"),
        ("8.8.4.4", "Google Public DNS"),
        ("1.1.1.1", "Cloudflare DNS"),
        ("1.0.0.1", "Cloudflare DNS"),
        ("9.9.9.9", "Quad9 DNS"),
        ("208.67.222.222", "OpenDNS"),
        ("208.67.220.220", "OpenDNS"),
        ("4.2.2.2", "Level3/CenturyLink DNS"),
    ]

    # Construimos el CSV final
    rows = []

    for ioc_hash, family, first_seen in malicious_hashes:
        rows.append({
            "ioc": ioc_hash,
            "ioc_type": "hash",
            "label": "malicious",
            "family_or_source": family,
            "first_seen": first_seen,
        })

    for domain in benign_domains:
        rows.append({
            "ioc": domain,
            "ioc_type": "domain",
            "label": "benign",
            "family_or_source": "Dominio de referencia con mucho tráfico",
            "first_seen": "",
        })

    for ip_address, source in benign_ips:
        rows.append({
            "ioc": ip_address,
            "ioc_type": "ip",
            "label": "benign",
            "family_or_source": source,
            "first_seen": "",
        })

    with open(OUTPUT_PATH, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=["ioc", "ioc_type", "label", "family_or_source", "first_seen"])
        writer.writeheader()
        writer.writerows(rows)

    print(f"\nDataset generado: {OUTPUT_PATH}")
    print(f"Total IOCs: {len(rows)}")
    print(f"  Maliciosos: {sum(1 for row in rows if row['label'] == 'malicious')}")
    print(f"  Benignos:    {sum(1 for row in rows if row['label'] == 'benign')}")

    # Lista de IOCs para el módulo de enriquecimiento (Apartado 2.5). UTF-8 sin BOM que es el
    # comportamiento por defecto de open() con encoding="utf-8"
    with open(IOCS_TXT_PATH, "w", encoding="utf-8") as f:
        for row in rows:
            f.write(row["ioc"] + "\n")
    print(f"Lista de IOCs para el módulo de enriquecimiento guardada en: {IOCS_TXT_PATH}")


if __name__ == "__main__":
    main()