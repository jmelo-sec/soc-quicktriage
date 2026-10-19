# build_track2.py
# Construye el dataset de alertas (tabla 3, apartado 3.2.1) para el Track 2, 
# a partir del archivo thursday_filtered.csv que genera filter_track2_columns.py.
#
# El escenario reúne dos técnicas de ataque del mismo actor (172.16.0.1) 
# contra el mismo objetivo (192.168.10.50):
#   - Brute Force (+ variante "Attempted"): 1365 eventos entre ~12:15 y ~13:00h
#   - SQL Injection (+ "Attempted"): 18 eventos entre ~13:35 y ~13:42h
#
# Los eventos de Brute Force son demasiados y muy repetidos, así que los agregamos
# en ventanas de tiempo fijo: cada ventana da un única alerta con su contador,
# imitando la compresión que hacen sistemas reales como AACT (Apartado 2.1.2.2).
# Los eventos de SQL Injection son pocos y cada uno importa, así que los mantenemos
# como alertas individuales.
#
# La ventana de agregación se elige comparando varios tamaños candidatos 
# (1, 5, 10, 15 min) y viendo cuántas alertas salen en cada uno; así la decisión
# final queda respaldada con datos.
# No hay que confundir esta ventana con la de 30 min que usa el grafo para 
# relacionar alertas ya construidas (Apartado 2.3.4).

import sys
import csv
import pandas as pd
import matplotlib.pyplot as plt

BRUTE_FORCE_LABELS = ["Web Attack - Brute Force", "Web Attack - Brute Force - Attempted"]
SQLI_LABELS = ["Web Attack - SQL Injection", "Web Attack - SQL Injection - Attempted"]

CANDIDATE_BIN_MINUTES = [1, 5, 10, 15]
CHOSEN_BIN_MINUTES = 5
OUTPUT_PATH = "track2_dataset.csv"


def main(input_path):
    print(f"Leyendo: {input_path}")

    df = pd.read_csv(input_path)
    df["Timestamp"] = pd.to_datetime(df["Timestamp"])

    relevant_labels = BRUTE_FORCE_LABELS + SQLI_LABELS
    scenario = df[df["Label"].isin(relevant_labels)].copy()

    print(f"Total eventos del escenario (Brute Force + SQL Injection): {len(scenario)}")

    # Comprobamos que se cumple la asunción de actor y objetivo únicos antes de seguir.
    # Es lo que sostiene la narrativa de correlación del Apartado 2.6.4.
    src_ips = scenario["Src IP"].unique()
    dst_ips = scenario["Dst IP"].unique()

    if len(src_ips) != 1 or len(dst_ips) != 1:
        print("Atención: Se esperaba un único Src IP y un único Dst IP en todo el escenario," \
              " pero existen varios. Revisar los datos antes de confiar en la narrativa de" \
              " correlación descrita en el Apartado 2.6.4.")
        print(f"  Src IPs encontradas: {list(src_ips)}")
        print(f"  Dst IPs encontradas: {list(dst_ips)}")
    else:
        print(f"Confirmado actor/objetivo único: {src_ips[0]} -> {dst_ips[0]}")

    alerts = []
    alert_id = 1

    # Comparamos varios tamaños de ventana antes de fijar el definitivo.
    bf_raw = scenario[scenario["Label"].isin(BRUTE_FORCE_LABELS)].copy()
    bin_comparison = []

    for minutes in CANDIDATE_BIN_MINUTES:
        n_bins = bf_raw["Timestamp"].dt.floor(f"{minutes}min").nunique()
        avg_events = len(bf_raw) / n_bins
        bin_comparison.append((minutes, n_bins, avg_events))

    print("\nComparativa de tamaños de ventana (agregación Brute Force):")
    print(f"{'Ventana (min)':<18}{'Alertas resultantes':<20}{'Media eventos/Alerta':<20}")

    for minutes, n_bins, avg_events in bin_comparison:
        marker = "  <- elegido" if minutes == CHOSEN_BIN_MINUTES else ""
        print(f"{minutes:<18}{n_bins:<20}{avg_events:<20.1f}{marker}")

    # Gráfica comparativa para la memoria: barra resaltada = ventana elegida.
    fig, ax = plt.subplots(figsize=(6, 4))
    sizes = [comparison[0] for comparison in bin_comparison]
    n_alerts = [comparison[1] for comparison in bin_comparison]
    colors = [
        "#1F6F87" if size == CHOSEN_BIN_MINUTES else "#D6EAF4" 
        for size in sizes
    ]

    ax.bar([f"{size} min" for size in sizes], n_alerts, color=colors)
    ax.set_ylabel("Alertas de Brute Force resultantes")
    ax.set_title("Track 2 - Alertas segun tamaño de ventana de agregación")

    for index, value in enumerate(n_alerts):
        ax.text(index, value + 0.3, str(value), ha="center", fontsize=10)

    fig.tight_layout()
    fig.savefig("track2_bin_size_comparison.png", dpi=150)
    print("Guardado en: track2_bin_size_comparison.png")
    print(f"\nUtilizo el tamaño de ventana elegido: {CHOSEN_BIN_MINUTES} minutos\n")

    # Brute Force: Agregamos en la ventana elegida
    bf = bf_raw.copy()
    bf["bin"] = bf["Timestamp"].dt.floor(f"{CHOSEN_BIN_MINUTES}min")

    for bin_start, group in bf.groupby("bin"):
        alerts.append({
            "alert_id": f"A{alert_id:04d}",
            "timestamp": bin_start.isoformat(),
            "source_ip": group["Src IP"].iloc[0],
            "dest_ip": group["Dst IP"].iloc[0],
            "rule_id": "WEB-BRUTE-FORCE",
            "rule_name": "Web Attack - Brute Force (aggregated)",
            "event_count": len(group),
        })
        alert_id += 1

    n_bf_alerts = alert_id - 1
    print(f"Brute Force: {len(bf)} eventos en bruto agregados en {n_bf_alerts} "
          f"Alertas (ventanas de {CHOSEN_BIN_MINUTES} min)")

    # SQL Injection: alertas individuales, que son pocos y cada uno cuenta.
    sqli = scenario[scenario["Label"].isin(SQLI_LABELS)].copy()
    sqli = sqli.sort_values("Timestamp")

    for _, event_row in sqli.iterrows():
        alerts.append({
            "alert_id": f"A{alert_id:04d}",
            "timestamp": event_row["Timestamp"].isoformat(),
            "source_ip": event_row["Src IP"],
            "dest_ip": event_row["Dst IP"],
            "rule_id": "WEB-SQL-INJECTION",
            "rule_name": "Web Attack - SQL Injection",
            "event_count": 1,
        })
        alert_id += 1

    n_sqli_alerts = alert_id - 1 - n_bf_alerts
    print(f"SQL Injection: {len(sqli)} eventos en bruto guardados como "
          f"{n_sqli_alerts} Alertas individuales")

    # Volcado final al CSV.
    alerts.sort(key=lambda alert: alert["timestamp"])

    with open(OUTPUT_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "alert_id", "timestamp", "source_ip", "dest_ip",
            "rule_id", "rule_name", "event_count",
        ])
        writer.writeheader()
        writer.writerows(alerts)

    print(f"\nDataset generado: {OUTPUT_PATH}")
    print(f"Total Alertas: {len(alerts)} "
          f"({n_bf_alerts} Brute Force, {n_sqli_alerts} SQL Injection)")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: python build_track2.py <path_to_thursday_filtered_csv>")
        sys.exit(1)
    main(sys.argv[1])