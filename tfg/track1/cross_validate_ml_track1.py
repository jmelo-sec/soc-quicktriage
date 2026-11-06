# cross_validate_ml_track1.py
# Validación cruzada repetida (5x10) para el Track 1.
# Se repite porque en el script original (train_evaluate_ml_track1.py) daba 1.000
# en todo, y hay sospechas de que es porque vt_malicious separa las clases casi sola.
# Aquí se repite el proceso con otras particiones, quitando las variables de VirusTotal
# para ver si AbuseIPDB y OTX siguen sirviendo de algo.
#
# Se reutiliza la carga de datos del script anterior para no tener código duplicado.
# Salida: track1_cv_repetida.csv

import csv
import json

import numpy as np
import matplotlib.pyplot as plt
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import RepeatedStratifiedKFold, cross_validate

from train_evaluate_ml_track1 import (
    DATASET_PATH, RESULTS_PATH, FEATURE_NAMES, RANDOM_STATE,
    load_labels, extract_features
)

OUTPUT_PATH = "track1_cross_validation.csv"
PLOT_PATH = "track1_cross_validation.png"

N_SPLITS = 5
N_REPEATS = 10

# Variables que se quitan en el escenario sin VirusTotal.
VIRUSTOTAL_FEATURES = ("vt_malicious", "vt_suspicious")

SCORING = {"bal_acc": "balanced_accuracy", "recall": "recall", "f1_mal": "f1"}


def build_dataset(labels, results):
    # Igual que en train_evaluate_ml_track1.py: una fila de variables por IOC etiquetado.
    X, y = [], []

    for result in results:
        ioc = result["ioc"]
        if ioc in labels:
            X.append(extract_features(result))
            y.append(1 if labels[ioc] == "malicious" else 0)  # 1 = malicious

    return np.array(X, dtype=float), np.array(y, dtype=int)


def main():
    labels = load_labels(DATASET_PATH)

    with open(RESULTS_PATH, encoding="utf-8") as f:
        results = json.load(f)

    X, y = build_dataset(labels, results)

    # Índices de las columnas de cada escenario.
    scenarios = {
        "Todas": list(range(len(FEATURE_NAMES))),
        "Sin VT": [i for i, name in enumerate(FEATURE_NAMES) if name not in VIRUSTOTAL_FEATURES],
    }

    models = {
        "Regresión Logística": LogisticRegression(max_iter=1000, class_weight="balanced"),
        "Random Forest": RandomForestClassifier(
            n_estimators=200, random_state=RANDOM_STATE, class_weight="balanced"
        ),
    }

    cv = RepeatedStratifiedKFold(n_splits=N_SPLITS, n_repeats=N_REPEATS, random_state=RANDOM_STATE)

    print(f"Muestras: {len(y)} ({y.sum()} maliciosos, {len(y) - y.sum()} benignos)")
    print(f"{N_SPLITS} particiones x {N_REPEATS} repeticiones = {N_SPLITS * N_REPEATS} evaluaciones por modelo")

    rows = []

    for scenario_name, columns in scenarios.items():
        print(f"\n>>> Escenario: {scenario_name} ({len(columns)} variables)")

        for model_name, model in models.items():
            scores = cross_validate(model, X[:, columns], y, cv=cv, scoring=SCORING)

            row = {"scenario": scenario_name, "model": model_name}

            for metric in SCORING:
                values = scores[f"test_{metric}"]
                row[f"{metric}_mean"] = round(values.mean(), 3)
                row[f"{metric}_std"] = round(values.std(), 3)

            rows.append(row)

            print(f"{model_name}: "
                  f"BA = {row['bal_acc_mean']:.3f} (std: {row['bal_acc_std']:.3f})  "
                  f"Recall = {row['recall_mean']:.3f} (std: {row['recall_std']:.3f})  "
                  f"F1 (malicious) = {row['f1_mal_mean']:.3f} (std: {row['f1_mal_std']:.3f})")

    with open(OUTPUT_PATH, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    print(f"\nResultados guardados en {OUTPUT_PATH}")
    
    # Balanced Accuracy media por escenario y modelo, con desviación como barra de error.
    model_colors = {"Regresión Logística": "#1F6F87", "Random Forest": "#12333F"}
    bar_width = 0.35

    fig, ax = plt.subplots(figsize=(6, 4))

    for offset, model_name in zip((-bar_width / 2, bar_width / 2), models):
        model_rows = [row for row in rows if row["model"] == model_name]
        positions = [i + offset for i in range(len(scenarios))]
        means = [row["bal_acc_mean"] for row in model_rows]
        stds = [row["bal_acc_std"] for row in model_rows]

        bars = ax.bar(positions, means, bar_width, yerr=stds, capsize=4,
                      color=model_colors[model_name], label=model_name)

        for bar, mean in zip(bars, means):
            ax.text(bar.get_x() + bar.get_width() / 2, 0.05, f"{mean:.3f}",
                    ha="center", fontsize=10, color="white")

    ax.set_xticks(range(len(scenarios)))
    ax.set_xticklabels(list(scenarios.keys()))
    ax.set_ylim(0, 1.2)
    ax.set_yticks([0, 0.2, 0.4, 0.6, 0.8, 1.0])
    ax.set_ylabel("Balanced Accuracy (media ± desviación)")
    ax.set_title(f"Track 1 - Validación cruzada repetida ({N_SPLITS}x{N_REPEATS})")
    ax.legend(loc="upper center", ncol=2, fontsize=9)
    fig.tight_layout()
    fig.savefig(PLOT_PATH, dpi=150)
    print(f"Guardado en: {PLOT_PATH}")

if __name__ == "__main__":
    main()