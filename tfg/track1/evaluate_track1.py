# evaluate_track1.py
# Cruza las etiquetas reales (track1_dataset.csv) con lo que predice quicktriage.py 
# (track1_results.json) y saca las métricas del apartado 3.2:# Balanced Accuracy, F1-score por clase 
# y matriz de confusión.

import csv
import json

import matplotlib.pyplot as plt
from sklearn.metrics import (
    balanced_accuracy_score,
    f1_score,
    confusion_matrix,
    classification_report,
    ConfusionMatrixDisplay,
)

DATASET_PATH = "track1_dataset.csv"
RESULTS_PATH = "track1_results.json"

# A partir de MEDIUM lo contamos como predicción "malicious"
MALICIOUS_VERDICTS = {"MEDIUM", "HIGH", "CRITICAL"}


def load_labels(path):
    # Leemos el CSV detectando el separador (',' o ';') y montamos un diccionario IOC -> label
    labels = {}

    with open(path, encoding="utf-8-sig") as f:
        sample = f.read(2048)
        f.seek(0)
        dialect = csv.Sniffer().sniff(sample, delimiters=",;")
        reader = csv.DictReader(f, dialect=dialect)

        for row in reader:
            labels[row["ioc"]] = row["label"]

    return labels


def load_results(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def main():
    labels = load_labels(DATASET_PATH)
    results = load_results(RESULTS_PATH)

    y_true = []
    y_pred = []
    rows_for_report = []

    # Cruzamos resultados con etiquetas reales. Los IOCs que no estén en el dataset 
    # los saltamos con un aviso.
    for result in results:
        ioc = result["ioc"]

        if ioc not in labels:
            print(f"Atención: Este IOC no está presente en el dataset, lo salto: {ioc}")
            continue

        true_label = labels[ioc]                # "malicious" o "benign"
        verdict = result["risk"]["verdict"]     # LOW / MEDIUM / HIGH / CRITICAL
        score = result["risk"]["score"]
        pred_label = "malicious" if verdict in MALICIOUS_VERDICTS else "benign"

        y_true.append(true_label)
        y_pred.append(pred_label)

        rows_for_report.append({
            "ioc": ioc,
            "ioc_type": result.get("ioc_type", ""),
            "true_label": true_label,
            "verdict": verdict,
            "score": score,
            "pred_label": pred_label,
            "correct": true_label == pred_label,
        })

    n = len(y_true)
    n_correct = sum(1 for report_row in rows_for_report if report_row["correct"])

    bal_acc = balanced_accuracy_score(y_true, y_pred)
    f1_malicious = f1_score(y_true, y_pred, pos_label="malicious")
    f1_benign = f1_score(y_true, y_pred, pos_label="benign")

    labels_order = ["malicious", "benign"]
    cm = confusion_matrix(y_true, y_pred, labels=labels_order)

    # -----------------------------------------------------------------
    # Matriz de confusión (para la memoria, apartado 3.2)
    # -----------------------------------------------------------------
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=labels_order)
    fig, ax = plt.subplots(figsize=(5, 5))
    disp.plot(ax=ax, cmap="Blues", colorbar=False, values_format="d")
    ax.set_title("Motor heurístico - Matriz de confusión (Track 1)")
    fig.tight_layout()
    fig.savefig("track1_confusion_matrix.png", dpi=150)
    print("Gráfica guardada en: track1_confusion_matrix.png")

    print("=" * 60)
    print("TRACK 1 - EVALUACIÓN DEL MOTOR HEURÍSTICO")
    print("=" * 60)
    print(f"Total IOCs evaluados: {n}")
    print(f"Predicciones correctas: {n_correct} ({100 * n_correct / n:.1f}%)")
    print(f"Regla de decisión: veredicto en {sorted(MALICIOUS_VERDICTS)} -> malicious")
    print()
    print(f"Balanced Accuracy: {bal_acc:.3f}")
    print(f"F1-score (malicious): {f1_malicious:.3f}")
    print(f"F1-score (benign):    {f1_benign:.3f}")
    print()
    print("Matriz de confusión (filas = etiqueta real, columnas = predicción)")
    print(f"                 pred_malicious  pred_benign")
    print(f"true_malicious   {cm[0][0]:>14}  {cm[0][1]:>11}")
    print(f"true_benign      {cm[1][0]:>14}  {cm[1][1]:>11}")
    print()
    print(classification_report(y_true, y_pred, labels=labels_order))

    # -----------------------------------------------------------------
    # Casos mal clasificados -- los comentamos en el Apartado 3.5
    # -----------------------------------------------------------------
    misclassified = [report_row for report_row in rows_for_report if not report_row["correct"]]

    print(f"Casos mal clasificados: {len(misclassified)}")

    for report_row in misclassified:
        print(f"  - {report_row['ioc'][:50]:<50} true={report_row['true_label']:<10} "
              f"pred={report_row['pred_label']:<10} veredicto={report_row['verdict']:<8} score={report_row['score']}")

    # -----------------------------------------------------------------
    # Detalle por IOC, para analizarlo después con más calma
    # -----------------------------------------------------------------
    out_path = "track1_evaluation_detail.csv"

    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows_for_report[0].keys()))
        writer.writeheader()
        writer.writerows(rows_for_report)

    print(f"\nDetalle guardado en: {out_path}")


if __name__ == "__main__":
    main()