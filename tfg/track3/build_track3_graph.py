# build_track3_graph.py
# Construye el grafo de correlación (apartado 2.3.4) a partir de las 10 alertas
# del Track 3 (track3_alerts.csv). Aplica los tres criterios de relación con
# regla OR y usa Louvain para detectar comunidades.
#
# Diferencias con el Track 2:
#
# 1. Infraestructura: los hashes tienen dest_ip vacío, así que no se cuenta
#    como coincidencia si ambas alertas tienen el campo vacío. Solo se aplica
#    cuando las dos tienen una IP y son iguales.
#
# 2. Ventana temporal: aquí los hashes (MalwareBazaar "recent") y las IPs de
#    C2 (ThreatFox) llevan first_seen real, así que la separación entre ambos
#    grupos depende de cuándo se generó el dataset y puede ser de horas, no de
#    días. Por eso las ventanas candidatas se prueban en horas y se elige la
#    más pequeña que reproduzca la misma partición que familia de amenaza.
#
# Familia de amenaza: se compara el rule_id. Aquí hay uno para los hashes y
# otro para las IPs de C2, así que el criterio solo relaciona alertas del
# mismo tipo.

import csv
from datetime import datetime
from itertools import combinations

import networkx as nx
import matplotlib.pyplot as plt


DATASET_PATH = "track3_alerts.csv"
CANDIDATE_WINDOWS_HOURS = [1, 2, 4, 8, 12, 24, 48]
CHOSEN_WINDOW_HOURS = None  # Se decide después de comparar las ventanas.


def parse_timestamp(raw):
    # Excel puede cambiar el formato del timestamp según la configuración
    # regional, así que probamos los que aparecen en los datos.
    ts = raw.strip()
    if ts.endswith(" UTC"):
        ts = ts[:-4]

    formatos = [
        "%Y-%m-%d %H:%M:%S",  # formato original: 2026-08-26 13:27:38
        "%d/%m/%Y %H:%M:%S",  # Excel, con segundos: 26/08/2026 13:27:38
        "%d/%m/%Y %H:%M",     # Excel, sin segundos: 26/08/2026 13:27
    ]
    for fmt in formatos:
        try:
            return datetime.strptime(ts, fmt)
        except ValueError:
            continue
    raise ValueError(f"No se reconoce el formato de este timestamp: {raw!r}")


def load_alerts(path):
    alerts = []
    with open(path, encoding="utf-8-sig") as f:
        sample = f.read(2048)
        f.seek(0)
        dialect = csv.Sniffer().sniff(sample, delimiters=",;")
        reader = csv.DictReader(f, dialect=dialect)
        for alert in reader:
            alert["timestamp"] = parse_timestamp(alert["timestamp"])
            alerts.append(alert)
    return alerts


def same_infrastructure(alert_a, alert_b):
    # Si alguna de las dos no tiene dest_ip real, no cuenta como
    # infraestructura compartida aunque las dos cadenas estén vacías.
    if not alert_a["dest_ip"] or not alert_b["dest_ip"]:
        return False
    return alert_a["dest_ip"] == alert_b["dest_ip"]


def within_temporal_window(alert_a, alert_b, window_hours):
    delta_hours = abs((alert_a["timestamp"] - alert_b["timestamp"]).total_seconds()) / 3600
    return delta_hours <= window_hours


def same_threat_family(alert_a, alert_b):
    return alert_a["rule_id"] == alert_b["rule_id"]


def compute_edges(alerts, window_hours):
    n = len(alerts)
    edges_infra = set()
    edges_temporal = set()
    edges_family = set()
    edges_combined = set()

    for i, j in combinations(range(n), 2):
        alert_a, alert_b = alerts[i], alerts[j]
        infra = same_infrastructure(alert_a, alert_b)
        temporal = within_temporal_window(alert_a, alert_b, window_hours)
        family = same_threat_family(alert_a, alert_b)

        if infra:
            edges_infra.add((i, j))
        if temporal:
            edges_temporal.add((i, j))
        if family:
            edges_family.add((i, j))
        if infra or temporal or family:
            edges_combined.add((i, j))

    return edges_infra, edges_temporal, edges_family, edges_combined


def main():
    alerts = load_alerts(DATASET_PATH)
    print(f"Se cargan {len(alerts)} Alertas desde {DATASET_PATH}")

    n = len(alerts)
    total_possible_pairs = n * (n - 1) // 2
    print(f"Total de pares de Alertas posibles: {total_possible_pairs}")

    # Calcula el criterio de familia antes de comparar ventanas, porque sirve
    # de referencia para elegir cuál usar.
    edges_family_global = set()
    for i, j in combinations(range(n), 2):
        if same_threat_family(alerts[i], alerts[j]):
            edges_family_global.add((i, j))

    # Comparativa de ventanas temporales (en horas)
    print("\nComparativa de ventanas temporales (aristas que generaría cada una, sola):")
    print(f"{'Ventana (horas)':<18}{'Aristas temporales':<22}{'% de los pares':<16}")
    window_comparison = []
    for hours in CANDIDATE_WINDOWS_HOURS:
        edges_t = set()
        for i, j in combinations(range(n), 2):
            if within_temporal_window(alerts[i], alerts[j], hours):
                edges_t.add((i, j))
        pct = 100 * len(edges_t) / total_possible_pairs
        window_comparison.append((hours, len(edges_t), pct))
        print(f"{hours:<18}{len(edges_t):<22}{pct:<16.1f}")

    fig_w, ax_w = plt.subplots(figsize=(6, 4))
    hours_list = [c[0] for c in window_comparison]
    n_edges_list = [c[1] for c in window_comparison]
    ax_w.bar([f"{h}h" for h in hours_list], n_edges_list, color="#1F6F87")
    ax_w.axhline(total_possible_pairs, color="#8a1f1f", linestyle="--", linewidth=1,
                 label=f"Total de pares posibles ({total_possible_pairs})")
    ax_w.set_ylabel("Aristas temporales generadas")
    ax_w.set_title("Track 3 - Aristas temporales según ventana (horas)")
    ax_w.legend()
    for i, v in enumerate(n_edges_list):
        ax_w.text(i, v + 0.5, str(v), ha="center", fontsize=10)
    fig_w.tight_layout()
    fig_w.savefig("track3_window_comparison.png", dpi=150)
    print("Guardado: track3_window_comparison.png")

    # Ventana más pequeña que genera la misma partición que familia de amenaza.
    chosen_window = None
    for hours in CANDIDATE_WINDOWS_HOURS:
        edges_t_check = set()
        for i, j in combinations(range(n), 2):
            if within_temporal_window(alerts[i], alerts[j], hours):
                edges_t_check.add((i, j))
        if edges_t_check == edges_family_global:
            chosen_window = hours
            break
    if chosen_window is None:
        # Si ninguna coincide, usa la mayor que no conecte todos los pares.
        for hours, n_edges, pct in window_comparison:
            if pct < 100:
                chosen_window = hours
    if chosen_window is None:
        raise RuntimeError(
            "Ninguna ventana candidata (en CANDIDATE_WINDOWS_HOURS) separa los grupos "
            "de esta ejecución: todas conectan el 100% de los pares o ninguna reproduce "
            "la partición por familia. Revisa el rango de fechas real de "
            "track3_alerts.csv (columna timestamp) y amplía/ajusta "
            "CANDIDATE_WINDOWS_HOURS en consecuencia."
        )
    print(f"\nVentana elegida: {chosen_window} horas (misma partición que Familia de Amenaza, sin forzar)\n")

    # Aristas finales con la ventana elegida
    edges_infra, edges_temporal, edges_family, edges_combined = compute_edges(alerts, chosen_window)

    print("Aristas que genera cada criterio, evaluado de forma aislada:")
    print(f"  Infraestructura (mismo dest_ip real): {len(edges_infra)} "
          f"({100 * len(edges_infra) / total_possible_pairs:.1f}% de los pares)")
    print(f"  Temporal (<= {chosen_window}h): {len(edges_temporal)} "
          f"({100 * len(edges_temporal) / total_possible_pairs:.1f}% de los pares)")
    print(f"  Familia de amenaza (mismo rule_id): {len(edges_family)} "
          f"({100 * len(edges_family) / total_possible_pairs:.1f}% de los pares)")
    print(f"  Combinado (regla OR, grafo final): {len(edges_combined)} "
          f"({100 * len(edges_combined) / total_possible_pairs:.1f}% de los pares)")

    fig, ax = plt.subplots(figsize=(7, 4))
    criteria = ["Infraestructura\n(sola)", "Temporal\n(sola)",
                "Familia amenaza\n(sola)", "Combinado\n(OR, grafo final)"]
    counts = [len(edges_infra), len(edges_temporal), len(edges_family), len(edges_combined)]
    colors = ["#D6EAF4", "#1F6F87", "#D6EAF4", "#12333F"]
    ax.bar(criteria, counts, color=colors)
    ax.axhline(total_possible_pairs, color="#8a1f1f", linestyle="--", linewidth=1,
               label=f"Total de pares posibles ({total_possible_pairs})")
    ax.set_ylabel("Número de pares de Alertas conectados")
    ax.set_title("Track 3 - Aristas generadas por cada criterio de correlación")
    ax.legend()
    for i, v in enumerate(counts):
        ax.text(i, v + 0.3, str(v), ha="center", fontsize=10)
    fig.tight_layout()
    fig.savefig("track3_edge_criteria_breakdown.png", dpi=150)
    print("\nGuardado: track3_edge_criteria_breakdown.png")

    # Grafo final: tres criterios combinados (regla OR) + Louvain
    G = nx.Graph()
    for idx, alert in enumerate(alerts):
        G.add_node(idx, alert_id=alert["alert_id"], rule_id=alert["rule_id"])
    G.add_edges_from(edges_combined)

    communities = nx.algorithms.community.louvain_communities(G, seed=42)
    print(f"\nDetección de comunidades con Louvain (3 criterios, regla OR): "
          f"{len(communities)} comunidades encontradas")
    for community_idx, community in enumerate(communities):
        rule_ids = {alerts[i]["rule_id"] for i in community}
        alert_ids = sorted(alerts[i]["alert_id"] for i in community)
        print(f"  Comunidad {community_idx + 1} ({len(community)} Alertas, "
              f"tipos de regla: {rule_ids}): {alert_ids}")

    # Visualización
    palette = ["#1F6F87", "#D6EAF4", "#12333F", "#3A6B7A"]
    node_color_map = {}
    for community_idx, community in enumerate(communities):
        for node in community:
            node_color_map[node] = palette[community_idx % len(palette)]
    node_colors = [node_color_map[i] for i in G.nodes()]
    labels = {i: alerts[i]["alert_id"] for i in G.nodes()}

    fig2, ax2 = plt.subplots(figsize=(9, 7))
    pos = nx.spring_layout(G, seed=42, k=0.8)
    nx.draw_networkx_edges(G, pos, ax=ax2, alpha=0.3, edge_color="#8a8a8a")
    nx.draw_networkx_nodes(G, pos, ax=ax2, node_color=node_colors,
                            edgecolors="#12333F", node_size=350)
    nx.draw_networkx_labels(G, pos, labels=labels, ax=ax2, font_size=8)
    ax2.set_title(f"Track 3 - Grafo de correlación, 3 criterios (regla OR) "
                  f"({len(communities)} comunidades)")
    ax2.axis("off")
    fig2.tight_layout()
    fig2.savefig("track3_graph_communities.png", dpi=150)
    print("Guardado: track3_graph_communities.png")


if __name__ == "__main__":
    main()