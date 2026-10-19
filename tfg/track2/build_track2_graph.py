# build_track2_graph.py
# Construye el grafo de correlación descrito en el Apartado 2.3.4 sobre
# las 28 alertas de track2_dataset.csv, aplicando los 3 criterios de arista
# (infraestructura, proximidad y familia de amenaza) con regla OR, y detecta
# campañas con Louvain.
#
# En este escenario las 28 alertas comparten el mismo par de IP origen/destino por 
# diseño (Apartado 2.6.4), así que el criterio de infraestructura no discrimina nada: 
# da True para cualquier par de alertas, tenga relación real o no. Medimos ese efecto 
# antes de combinar criterios, mostrando por separado cuántas aristas genera cada uno.
# Es una propiedad de este escenario concreto (un solo actor), no una limitación general 
# del criterio, que sí discriminaría en escenarios con varios actores u objetivos (Apartado 4.3).
#
# Criterio Temporal: dos alertas se conectan si sus timestamps distan menos de  
# TEMPORAL_WINDOW_MINUTES (30 min por defecto, Apartado 2.3.4).
#
# Criterio de Familia de Amenaza: 2 alertas se conectan si comparten rule_id

import csv
from datetime import datetime
from itertools import combinations

import networkx as nx
import matplotlib.pyplot as plt

DATASET_PATH = "track2_dataset.csv"
TEMPORAL_WINDOW_MINUTES = 30

def load_alerts(path):
    alerts = []

    with open(path, encoding="utf-8-sig") as f:
        # Autodetectamos el separador (',' o ';') porque al reguardar un CSV desde Excel
        # con la configuración regional española a veces cambia a ';' sin avisar.
        sample = f.read(2048)
        f.seek(0)
        dialect = csv.Sniffer().sniff(sample, delimiters=",;")
        reader = csv.DictReader(f, dialect=dialect)

        for alert in reader:
            alert["timestamp"] = datetime.fromisoformat(alert["timestamp"])
            alerts.append(alert)

    return alerts

def same_infrastructure(alert_a, alert_b):
    return (
        alert_a["source_ip"] == alert_b["source_ip"] 
        and alert_a["dest_ip"] == alert_b["dest_ip"]
    )

def within_temporal_window(alert_a, alert_b, window_minutes):
    delta = abs(
        (alert_a["timestamp"] - alert_b["timestamp"]).total_seconds()
        ) / 60
    return delta <= window_minutes

def same_threat_family(alert_a, alert_b):
    return alert_a["rule_id"] == alert_b["rule_id"]

def main():
    alerts = load_alerts(DATASET_PATH)
    print(f"Se cargan {len(alerts)} Alertas desde {DATASET_PATH}")

    # Paso 1: Medimos cada criterio por separado, antes de combinarlos, para
    # dejar clara la saturación de infraestructura en este escenario.
    n = len(alerts)
    total_possible_pairs = n * (n - 1) // 2

    edges_infra_only = set()
    edges_temporal_only = set()
    edges_family_only = set()
    edges_combined = set()

    for i, j in combinations(range(n), 2):
        alert_a, alert_b = alerts[i], alerts[j]
        infra = same_infrastructure(alert_a, alert_b)
        temporal = within_temporal_window(
            alert_a, alert_b, TEMPORAL_WINDOW_MINUTES
        )
        family = same_threat_family(alert_a, alert_b)

        if infra:
            edges_infra_only.add((i, j))
        if temporal:
            edges_temporal_only.add((i, j))
        if family:
            edges_family_only.add((i, j))
        if infra or temporal or family:
            edges_combined.add((i, j))

    print(f"\nTotal de pares de Alertas posibles: {total_possible_pairs}")
    print("Aristas que genera cada criterio, evaluado de forma aislada:")
    print(f"  Infraestructura (misma src/dst IP): {len(edges_infra_only)} "
          f"({100 * len(edges_infra_only) / total_possible_pairs:.1f}% de los pares)")
    print(f"  Temporal (<= {TEMPORAL_WINDOW_MINUTES} min):              "
          f"{len(edges_temporal_only)} "
          f"({100 * len(edges_temporal_only) / total_possible_pairs:.1f}% de los pares)")
    print(f"  Familia de Amenaza (mismo rule_id):     {len(edges_family_only)} "
          f"({100 * len(edges_family_only) / total_possible_pairs:.1f}% de los pares)")
    print(f"  Combinado (regla OR, grafo final):  {len(edges_combined)} "
          f"({100 * len(edges_combined) / total_possible_pairs:.1f}% de los pares)")

    if len(edges_infra_only) == total_possible_pairs:
        print("\nAtención: el criterio de infraestructura por sí solo conecta todos "
              "los pares posibles de Alertas de este dataset (100%), confirmando "
              "que no discrimina nada en este escenario de actor único (Apartado 2.6.4). "
              "La estructura final del grafo la determinan entonces el criterio "
              "temporal y el de Familia de Amenaza.")

    # Gráfico de barras del desglose por criterio.
    fig, ax = plt.subplots(figsize=(7, 4))
    criteria = ["Infraestructura\n(solo)", "Temporal\n(solo)",
                "Familia de Amenaza(solo)", "Combinado\n(regla OR, grafo final)"]
    counts = [len(edges_infra_only), len(edges_temporal_only),
              len(edges_family_only), len(edges_combined)]
    colors = ["#D6EAF4", "#1F6F87", "#D6EAF4", "#12333F"]

    ax.bar(criteria, counts, color=colors)
    ax.axhline(total_possible_pairs, color="#8a1f1f", linestyle="--", linewidth=1,
               label=f"Total de pares posibles ({total_possible_pairs})")
    ax.set_ylabel("Número de pares de Alertas conectados")
    ax.set_title("Track 2 - Aristas generadas por cada criterio de correlación")
    ax.legend()

    for i, v in enumerate(counts):
        ax.text(i, v + 5, str(v), ha="center", fontsize=10)

    fig.tight_layout()
    fig.savefig("track2_edge_criteria_breakdown.png", dpi=150)
    print("\nGuardado en: track2_edge_criteria_breakdown.png")

    # Paso 2: Grafo de final con la regla OR combinada (Apartado 2.3.4) y 
    # detección de comunidades con Louvain.
    G = nx.Graph()

    for idx, alert in enumerate(alerts):
        G.add_node(idx, alert_id=alert["alert_id"], rule_id=alert["rule_id"],
                   timestamp=alert["timestamp"])

    G.add_edges_from(edges_combined)

    communities = nx.algorithms.community.louvain_communities(G, seed=42)
    print(f"\nDetección de comunidades con Louvain (3 criterios, regla OR): "
          f"{len(communities)} comunidades encontradas")

    for community_idx, community in enumerate(communities):
        rule_ids = {alerts[i]["rule_id"] for i in community}
        alert_ids = sorted(alerts[i]["alert_id"] for i in community)
        print(f"  Comunidad {community_idx + 1} ({len(community)} Alertas, "
              f"tipos de regla: {rule_ids}): {alert_ids}")

    # Paso 2b: Análisis secundario sin el criterio de infraestructura, que ya 
    # sabemos que está saturado. Es una comparativa diagnóstica para ver qué 
    # estructura revela el grafo al quitar el criterio saturado (Apartados 3.3 y 3.5).
    G_no_infra = nx.Graph()

    for idx, alert in enumerate(alerts):
        G_no_infra.add_node(idx, alert_id=alert["alert_id"], rule_id=alert["rule_id"])

    edges_no_infra = edges_temporal_only | edges_family_only
    G_no_infra.add_edges_from(edges_no_infra)

    communities_no_infra = nx.algorithms.community.louvain_communities(
        G_no_infra, 
        seed=42
    )
    print(f"\nDetección de comunidades con Louvain (solo temporal + Familia de Amenaza, "
          f"sin infraestructura): {len(communities_no_infra)} comunidades encontradas")

    for community_idx, community in enumerate(communities_no_infra):
        rule_ids = {alerts[i]["rule_id"] for i in community}
        alert_ids = sorted(alerts[i]["alert_id"] for i in community)
        print(f"  Comunidad {community_idx + 1} ({len(community)} Alertas, "
              f"tipos de regla: {rule_ids}): {alert_ids}")

    # Visualización del grafo, coloreado por comunidad detectada.
    palette = ["#1F6F87", "#D6EAF4", "#12333F", "#3A6B7A"]
    node_color_map = {}

    for community_idx, community in enumerate(communities):
        for node in community:
            node_color_map[node] = palette[community_idx % len(palette)]

    node_colors = [node_color_map[i] for i in G.nodes()]

    labels = {i: alerts[i]["alert_id"] for i in G.nodes()}

    fig2, ax2 = plt.subplots(figsize=(9, 7))
    pos = nx.spring_layout(G, seed=42, k=0.6)
    nx.draw_networkx_edges(G, pos, ax=ax2, alpha=0.3, edge_color="#8a8a8a")
    nx.draw_networkx_nodes(G, pos, ax=ax2, node_color=node_colors,
                            edgecolors="#12333F", node_size=350)
    nx.draw_networkx_labels(G, pos, labels=labels, ax=ax2, font_size=7)
    ax2.set_title(f"Track 2 - Grafo de correlación, 3 criterios (regla OR) "
                  f"({len(communities)} comunidad)")
    ax2.axis("off")
    fig2.tight_layout()
    fig2.savefig("track2_graph_communities.png", dpi=150)
    print("Guardado en: track2_graph_communities.png")

    # Misma visualización para el análisis secundario (sin infraestructura),
    # donde sí se ve la estructura de comunidades.
    node_color_map_2 = {}

    for community_idx, community in enumerate(communities_no_infra):
        for node in community:
            node_color_map_2[node] = palette[community_idx % len(palette)]

    node_colors_2 = [node_color_map_2[i] for i in G_no_infra.nodes()]

    fig3, ax3 = plt.subplots(figsize=(9, 7))
    pos2 = nx.spring_layout(G_no_infra, seed=42, k=0.8)
    nx.draw_networkx_edges(G_no_infra, pos2, ax=ax3, alpha=0.3, edge_color="#8a8a8a")
    nx.draw_networkx_nodes(G_no_infra, pos2, ax=ax3, node_color=node_colors_2,
                            edgecolors="#12333F", node_size=350)
    nx.draw_networkx_labels(G_no_infra, pos2, labels=labels, ax=ax3, font_size=7)
    ax3.set_title(f"Track 2 - Grafo de correlación, solo temporal + Familia de Amenaza "
                  f"({len(communities_no_infra)} comunidades)")
    ax3.axis("off")
    fig3.tight_layout()
    fig3.savefig("track2_graph_communities_no_infra.png", dpi=150)
    print("Guardado en: track2_graph_communities_no_infra.png")

if __name__ == "__main__":
    main()