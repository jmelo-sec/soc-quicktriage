# build_track3.py
# Construye el dataset de IOCs del Track 3 (track3_dataset.csv). Selecciona la familia 
# maliciosa más numerosa del Track 1 y consulta ThreatFox para obtener IPs de C2 reales 
# de esa misma familia.
#
# La familia no se fija a mano. Como build_track1.py consulta las muestras recientes de 
# MalwareBazaar, la familia más numerosa puede cambiar entre ejecuciones; así el Track 3 
# se adapta al dataset generado sin intervención.
#
# Pasos:
#   1. Contar los IOCs maliciosos de track1_dataset.csv por familia.
#   2. Para cada familia candidata (de más a menos numerosa, y con al menos
#      MIN_HASHES_REQUIRED hashes en Track 1), resolver TODOS los slugs internos que
#      ThreatFox asocia a ese nombre (get_label puede devolver varias variantes, p.ej.
#      win.mirai y elf.mirai para "Mirai") y probar cada uno hasta encontrar uno con
#      al menos MIN_IPS_REQUIRED IPs de C2 (ip:port) distintas.
#   3. Elegir la primera familia (y el primer slug de esa familia) que cumpla el
#      mínimo de IPs. Si ninguna combinación cumple, se termina con error y no se
#      genera el dataset.
#   4. Combinar los hashes de esa familia (hasta MAX_HASHES) con el mismo número de IPs 
#      de C2, para un total de 10 IOCs.
#
# Fuente: ThreatFox (abuse.ch). API pública, requiere Auth-Key gratuita (auth.abuse.ch). 
# Documentación: threatfox.abuse.ch/api/

import sys
import csv
import requests

THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1/"
TRACK1_DATASET_PATH = "../track1/track1_dataset.csv"
OUTPUT_PATH = "track3_dataset.csv"

MAX_HASHES = 5           # Tope de hashes a reutilizar del Track 1.
MIN_IPS_REQUIRED = 5     # Mínimo de IPs de C2 distintas para aceptar la familia.
MIN_HASHES_REQUIRED = 3  # Mínimo de hashes en Track1 para considerar la familia.


def load_track1_malicious_by_family(path):
    # Lee track1_dataset.csv y agrupa los IOCs maliciosos por familia, ordenándolos de mayor a menor.
    by_family = {}
    with open(path, encoding="utf-8-sig") as f:
        sample = f.read(2048)
        f.seek(0)
        dialect = csv.Sniffer().sniff(sample, delimiters=",;")
        reader = csv.DictReader(f, dialect=dialect)
        for row in reader:
            if row["label"] != "malicious":
                continue
            family = row["family_or_source"]
            by_family.setdefault(family, []).append((row["ioc"], row["first_seen"]))

    return sorted(by_family.items(), key=lambda item: len(item[1]), reverse=True)


def resolve_threatfox_slugs(auth_key, family_name):
    # Traduce el nombre de familia de MalwareBazaar (p.ej. "Mirai") a TODOS los slugs
    # internos que ThreatFox asocia a ese nombre (p.ej. win.mirai, elf.mirai), usando
    # la query get_label. Puede haber varias variantes con volúmenes de IOCs muy
    # distintos, así que no nos quedamos solo con la primera.
    headers = {"Auth-Key": auth_key}
    data = {"query": "get_label", "malware": family_name}
    response = requests.post(THREATFOX_API_URL, headers=headers, json=data, timeout=30)
    response.raise_for_status()
    response_data = response.json()

    if response_data.get("query_status") != "ok":
        return []

    matches = response_data.get("data", [])
    return [m.get("malware") for m in matches if m.get("malware")]

def query_threatfox_ips(auth_key, malware_family, limit=50):
    headers = {"Auth-Key": auth_key}
    data = {"query": "malwareinfo", "malware": malware_family, "limit": limit}
    response = requests.post(THREATFOX_API_URL, headers=headers, json=data, timeout=30)
    response.raise_for_status()
    response_data = response.json()

    if response_data.get("query_status") != "ok":
        return []

    ips_seen = {}
    for ioc_entry in response_data.get("data", []):
        if ioc_entry.get("ioc_type") != "ip:port":
            continue
        ip = ioc_entry["ioc"].split(":")[0]
        if ip not in ips_seen:
            ips_seen[ip] = ioc_entry.get("first_seen", "")

    return list(ips_seen.items())

def select_family(auth_key, ranked_families):
    # Recorre las familias del Track 1 de más a menos numerosa (con suficientes
    # hashes) y, para cada una, prueba todos los slugs de ThreatFox que le
    # correspondan hasta encontrar uno con suficientes IPs de C2 reales.
    for family_name, hashes in ranked_families:
        if len(hashes) < MIN_HASHES_REQUIRED:
            print(f"\nFamilia: {family_name} tiene solo {len(hashes)} hashes "
                  f"(< {MIN_HASHES_REQUIRED}), se descarta sin consultar ThreatFox.")
            continue

        print(f"\nProbando familia: {family_name} ({len(hashes)} hashes en Track 1)")
        slugs = resolve_threatfox_slugs(auth_key, family_name)
        if not slugs:
            print(f"  ThreatFox no reconoce '{family_name}', se descarta.")
            continue

        for slug in slugs:
            print(f"  Probando slug: {slug}")
            ips = query_threatfox_ips(auth_key, slug, limit=50)
            print(f"    IPs de C2 distintas encontradas: {len(ips)}")
            if len(ips) >= MIN_IPS_REQUIRED:
                return family_name, slug, hashes, ips

        print(f"  Ningún slug de '{family_name}' tiene {MIN_IPS_REQUIRED} o más "
              f"IPs distintas, se descarta.")

    return None, None, None, None

def main():
    if len(sys.argv) != 2:
        print("Uso: python build_track3.py <TU_AUTH_KEY_DE_THREATFOX>")
        sys.exit(1)

    auth_key = sys.argv[1]

    print(f"Leyendo familias maliciosas desde {TRACK1_DATASET_PATH}...")
    ranked_families = load_track1_malicious_by_family(TRACK1_DATASET_PATH)
    print("Familias del Track 1, de mas a menos numerosa:")
    for family_name, hashes in ranked_families:
        print(f"  {family_name}: {len(hashes)}")

    family_name, slug, hashes, ips = select_family(auth_key, ranked_families)

    if family_name is None:
        print(f"\nAtención: ninguna familia del Track 1 tiene {MIN_IPS_REQUIRED} "
              f"o más IPs de C2 distintas en ThreatFox. No se genera el dataset.")
        sys.exit(1)

    n_hashes = min(MAX_HASHES, len(hashes))
    chosen_hashes = hashes[:n_hashes]
    n_ips = n_hashes  # Igualamos IPs a hashes para mantener el total en 10 IOCs.
    chosen_ips = ips[:n_ips]

    print(f"\nFamilia elegida: {family_name} (slug ThreatFox: {slug})")
    print(f"Usando {n_hashes} hashes del Track 1 y {n_ips} IPs de C2 de ThreatFox.")

    rows = []
    for ioc_hash, first_seen in chosen_hashes:
        rows.append({
            "ioc": ioc_hash,
            "ioc_type": "hash",
            "label": "malicious",
            "family_or_source": f"{family_name} (MalwareBazaar, reutilizado del Track 1)",
            "first_seen": first_seen,
        })

    for ip, first_seen in chosen_ips:
        rows.append({
            "ioc": ip,
            "ioc_type": "ip",
            "label": "malicious",
            "family_or_source": f"{family_name} C2 (ThreatFox)",
            "first_seen": first_seen,
        })

    with open(OUTPUT_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["ioc", "ioc_type", "label", "family_or_source", "first_seen"])
        writer.writeheader()
        writer.writerows(rows)

    print(f"\nDataset generado: {OUTPUT_PATH}")
    print(f"Total IOCs: {len(rows)} ({n_hashes} hashes, {n_ips} IPs)")
    print(f"Todos reales, todos etiquetados como {family_name}.")

    iocs_path = "iocs_track3.txt"
    with open(iocs_path, "w", newline="\n", encoding="utf-8") as f:
        f.write("\n".join(row["ioc"] for row in rows))

    print(f"Lista de IOCs para el módulo de enriquecimiento guardada en: {iocs_path}")

if __name__ == "__main__":
    main()