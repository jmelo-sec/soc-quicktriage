# train_evaluate_ml_track1.py
# Entrena y evalúa los 2 modelos de ML (Logistic Regression y Random Forest) 
# sobre el dataset Track 1, usando las mismas señales de enriquecimiento 
# que produce el motor heurístico (quicktriage.py). Las compara contra la 
# heurística, recalculada aquí con la misma regla que evaluate_track1.py.
#
# Features: vt_malicious, vt_suspicious, abuse_confidence, abuse_total_reports, 
# otx_pulse_count, otx_tag_count (tabla 5, Apartado 2.6.1)
#
# Atención con el tamaño de muestra: con 58 IOCs etiquetados, la validación cruzada 5-fold
# deja folds de menos de 10 muestras, lo que limita la fiabilidad estadística.
# Por eso utilizo un split 70/30, en lugar de 80/20, para mantener un conjunto de test 
# más representativo dado el pequeño tamaño de muestra. La limitación se reconoce 
# en el Apartado 3.5; la comparación sigue siendo válida como primera pasada.

import csv
import json

import numpy as np
import matplotlib.pyplot as plt
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from sklearn.metrics import balanced_accuracy_score, f1_score, ConfusionMatrixDisplay, confusion_matrix

DATASET_PATH = "track1_dataset.csv"
RESULTS_PATH = "track1_results.json"

# Misma regla que evaluate_track1.py; hay que mantenerlas sincronizadas.
MALICIOUS_VERDICTS = {"MEDIUM", "HIGH", "CRITICAL"}

FEATURE_NAMES = [
    "vt_malicious",
    "vt_suspicious",
    "abuse_confidence",
    "abuse_total_reports",
    "otx_pulse_count",
    "otx_tag_count",
]

TEST_SIZE = 0.3
RANDOM_STATE = 42


def load_labels(path):
    # Igual que en evaluate_track1.py: detectamos el separador y montamos un diccionario ioc -> label.
    labels = {}

    with open(path, encoding="utf-8-sig") as f:
        sample = f.read(2048)
        f.seek(0)
        dialect = csv.Sniffer().sniff(sample, delimiters=",;")
        reader = csv.DictReader(f, dialect=dialect)

        for row in reader:
            labels[row["ioc"]] = row["label"]

    return labels


def extract_features(entry):
    # Extrae las 6 variables predictoras de un resultado JSON de quicktriage.py.
    # Los "or 0" cubren el caso de que la fuente devuelve 'None' o falte.
    sources = entry.get("sources", {})
    vt = sources.get("virustotal", {})
    abuse = sources.get("abuseipdb", {})
    otx = sources.get("otx", {})

    return [
        vt.get("malicious", 0) or 0,
        vt.get("suspicious", 0) or 0,
        abuse.get("abuseConfidenceScore", 0) or 0,
        abuse.get("totalReports", 0) or 0,
        otx.get("pulse_count", 0) or 0,
        len(otx.get("tags", []) or []),
    ]


def heuristic_prediction(entry):
    # Reproduce la predicción binaria de la heurística a partir del veredicto.
    verdict = entry["risk"]["verdict"]
    return 1 if verdict in MALICIOUS_VERDICTS else 0


def main():
    labels = load_labels(DATASET_PATH)

    with open(RESULTS_PATH, encoding="utf-8") as f:
        results = json.load(f)

    X, y, y_heuristic, iocs = [], [], [], []

    for result in results:
        ioc = result["ioc"]
        if ioc not in labels:
            continue
        X.append(extract_features(result))
        y.append(1 if labels[ioc] == "malicious" else 0)  # 1 = malicious
        y_heuristic.append(heuristic_prediction(result))
        iocs.append(ioc)

    X = np.array(X, dtype=float)
    y = np.array(y, dtype=int)
    y_heuristic = np.array(y_heuristic, dtype=int)

    print("=" * 60)
    print("TRACK 1 - ENTRENAMIENTO Y EVALUACIÓN DE MODELOS ML")
    print("=" * 60)
    print(f"Total muestras: {len(y)} ({y.sum()} maliciosos, {len(y) - y.sum()} benignos)")
    print(f"Características: {FEATURE_NAMES}")
    print()

    # Validación cruzada 5-fold estratificada.
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=RANDOM_STATE)

    models = {
        "Regresión Logística": LogisticRegression(max_iter=1000, class_weight="balanced"),
        "Random Forest": RandomForestClassifier(
            n_estimators=200, random_state=RANDOM_STATE, class_weight="balanced"
        ),
    }

    for model_name, model in models.items():
        scores = cross_val_score(model, X, y, cv=cv, scoring="balanced_accuracy")
        print(f"{model_name} -- 5-fold CV Balanced Accuracy: "
              f"mean={scores.mean():.3f}  std={scores.std():.3f}  folds={np.round(scores, 3)}")
        
    print()

    # Holdout split 70/30, en lugar de 80/20 debido al tamaño de la muestra.
    X_train, X_test, y_train, y_test, ioc_train, ioc_test = train_test_split(
        X, y, iocs, test_size=TEST_SIZE, stratify=y, random_state=RANDOM_STATE
    )

    print(f"Holdout split ({int((1 - TEST_SIZE) * 100)}/{int(TEST_SIZE * 100)}): "
          f"{len(y_train)} train / {len(y_test)} test "
          f"({y_test.sum()} malicious, {len(y_test) - y_test.sum()} benign in test)")
    print()

    # La heurística la recalculamos solo sobre el subset de test, para que la comparación con 
    # los modelos ML sea justa.
    test_idx = [iocs.index(ioc) for ioc in ioc_test]
    y_heuristic_test = y_heuristic[test_idx]

    bal_acc_heuristic = balanced_accuracy_score(y_test, y_heuristic_test)
    f1_heuristic_mal = f1_score(y_test, y_heuristic_test, pos_label=1)
    f1_heuristic_ben = f1_score(y_test, y_heuristic_test, pos_label=0)

    print(f"--- Motor Heurístico (mismo subset de test, n={len(y_test)}) ---")
    print(f"Balanced Accuracy: {bal_acc_heuristic:.3f}")
    print(f"F1 (malicious): {f1_heuristic_mal:.3f}  |  F1 (benign): {f1_heuristic_ben:.3f}")
    print()

    ml_metrics = {}
    fig_cm, axes_cm = plt.subplots(1, 2, figsize=(10, 5))

    for ax, (model_name, model) in zip(axes_cm, models.items()):
        model.fit(X_train, y_train)
        y_pred = model.predict(X_test)

        bal_acc = balanced_accuracy_score(y_test, y_pred)
        f1_mal = f1_score(y_test, y_pred, pos_label=1)
        f1_ben = f1_score(y_test, y_pred, pos_label=0)
        cm = confusion_matrix(y_test, y_pred, labels=[1, 0])

        ml_metrics[model_name] = {
            "bal_acc": bal_acc, 
            "f1_mal": f1_mal, 
            "f1_ben": f1_ben, 
            "model": model,
        }

        print(f"--- {model_name} (holdout test set, n={len(y_test)}) ---")
        print(f"Balanced Accuracy: {bal_acc:.3f}")
        print(f"F1 (malicious): {f1_mal:.3f}  |  F1 (benign): {f1_ben:.3f}")
        print("Matriz de Confusión (filas=true, columnas=pred) [malicious, benign]:")
        print(cm)

        # En RF (Random Forest) miramos importancias; en LR (Logistic Regression), coeficientes.
        # Son las 2 formas de ver qué pesa más en cada modelo.
        if hasattr(model, "feature_importances_"):
            print("Importancia de Características:")

            for feature_name, importance in sorted(
                zip(FEATURE_NAMES, model.feature_importances_), key=lambda item: -item[1]
            ):
                print(f"  {feature_name:<22} {importance:.3f}")

        elif hasattr(model, "coef_"):
            print("Coeficientes:")

            for feature_name, coef in sorted(
                zip(FEATURE_NAMES, model.coef_[0]), key=lambda item: -abs(item[1])
            ):
                
                print(f"  {feature_name:<22} {coef:+.3f}")

        print()

        disp = ConfusionMatrixDisplay(
            confusion_matrix=cm, 
            display_labels=["malicious", "benign"]
        )
        disp.plot(ax=ax, cmap="Blues", colorbar=False, values_format="d")
        ax.set_title(model_name)

    fig_cm.suptitle("Track 1 - Matrices de Confusión (Modelos ML, holdout test set)")
    fig_cm.tight_layout()
    fig_cm.savefig("track1_confusion_matrices_ml.png", dpi=150)
    print("Guardado en: track1_confusion_matrices_ml.png")

    # Importancia de Características del Random Forest
    rf_model = ml_metrics["Random Forest"]["model"]
    importances = rf_model.feature_importances_
    order = np.argsort(importances)  # ascending, for a horizontal bar chart

    fig_fi, ax_fi = plt.subplots(figsize=(7, 4))
    ax_fi.barh(
        [FEATURE_NAMES[i] for i in order],
        [importances[i] for i in order],
        color="#1F6F87",
    )
    ax_fi.set_xlabel("Importancia")
    ax_fi.set_title("Track 1 - Importancia de Características (Random Forest)")
    fig_fi.tight_layout()
    fig_fi.savefig("track1_feature_importance.png", dpi=150)
    print("Guardado en: track1_feature_importance.png")

    # Comparativa Heurística vs ML (Balanced Accuracy)
    approach_names = ["Heurística", "Regresión Logística", "Random Forest"]
    bal_accs = [
        bal_acc_heuristic,
        ml_metrics["Regresión Logística"]["bal_acc"],
        ml_metrics["Random Forest"]["bal_acc"],
    ]

    fig_cmp, ax_cmp = plt.subplots(figsize=(6, 4))
    bars = ax_cmp.bar(approach_names, bal_accs, color=["#D6EAF4", "#1F6F87", "#12333F"])
    ax_cmp.set_ylim(0, 1.05)
    ax_cmp.set_ylabel("Balanced Accuracy")
    ax_cmp.set_title("Track 1 - Heurística vs ML (mismo subset de test)")

    for bar, value in zip(bars, bal_accs):
        ax_cmp.text(
            bar.get_x() + bar.get_width() / 2, 
            value + 0.02, 
            f"{value:.3f}",
            ha="center", fontsize=10
        )
    
    fig_cmp.tight_layout()
    fig_cmp.savefig("track1_heuristic_vs_ml.png", dpi=150)
    print("Guardado en: track1_heuristic_vs_ml.png")

if __name__ == "__main__":
    main()