# filter_track2_columns.py
# Filtra el CSV completo de 91 columnas del escenario Thursday de CICIDS2017 
# (versión corregida, Liu et al. 2022), y deja solo las 8 columnas que hacen
# falta para el modelo de alerta (Tabla 3, Apartado 2.3.1) y el grafo de correlación 
# (Apartado 2.3.4).
#
# Se lee en chunks para no cargar el dataset entero en memoria de golpe, ya que son
# millones de filas.
#
# Validamos también la columna 'Timestamp': descartamos y contamos las filas cuyo       
# valor no se pueda parsear como fecha/hora, porque el grafo de correlación (Apartado 2.3.4)
# compara timestamps entre alertas para decidir las aristas temporales y un valor inválido 
# rompería esa comparación.

import sys
import pandas as pd

COLUMNS_NEEDED = [
    "id",
    "Flow ID",
    "Src IP",
    "Dst IP",
    "Src Port",
    "Dst Port",
    "Timestamp",
    "Label",
]

CHUNK_SIZE = 100_000
OUTPUT_PATH = "thursday_filtered.csv"

def main(input_path):
    print(f"Leyendo: {input_path}")
    print(f"Columnas a extraer: {COLUMNS_NEEDED}")

    # Comprobamos la cabecera para confirmar los nombres exactos de las columnas,
    # a veces cambian entre mirrors del dataset (mayúsculas, espacios...).
    header = pd.read_csv(input_path, nrows=0)
    available = list(header.columns)
    missing = [c for c in COLUMNS_NEEDED if c not in available]
    if missing:
        print(f"Atención: Estas columnas no aparecen tal cual en el archivo: {missing}")
        print("Columnas disponibles en el archivo:")
        for c in available:
            print(f"  - {c!r}")
        print("Revisa si hay diferencias en los nombres de las columnas (espacios extra, "
              "mayúsculas/minúsculas) y ajusta COLUMNS_NEEDED antes de volver a ejecutarlo.")
        sys.exit(1)

    first_chunk = True
    total_rows = 0
    unparseable_timestamps = 0

    for chunk in pd.read_csv(input_path, usecols=COLUMNS_NEEDED, chunksize=CHUNK_SIZE):
        # Las filas con Timestamp inválido no sirven para el grafo (Apartado 2.3.4), así que 
        # las descartamos y contamos para dejarlo documentado.
        # dayfirst=True porque el dataset de CICIDS2017 usa formato dd/mm/yy.
        parsed = pd.to_datetime(chunk["Timestamp"], errors="coerce", dayfirst=True)
        bad_mask = parsed.isna()
        n_bad = int(bad_mask.sum())
        if n_bad:
            unparseable_timestamps += n_bad
            chunk = chunk.loc[~bad_mask].copy()

        chunk.to_csv(
            OUTPUT_PATH,
            mode="w" if first_chunk else "a",
            header=first_chunk,
            index=False,
        )
        first_chunk = False
        total_rows += len(chunk)
        print(f"  procesadas {total_rows:,} filas válidas hasta ahora "
              f"({unparseable_timestamps} timestamps inválidos descartados)...")

    print(f"\nListo. Archivo filtrado guardado en: {OUTPUT_PATH}")
    print(f"Total filas válidas: {total_rows:,}")
    if unparseable_timestamps:
        print(f"Atención: Se han descartado {unparseable_timestamps} filas por tener "
              f"un Timestamp inválido. No se incluyen en el archivo de salida.")
    else:
        print("Todos los timestamps se han parseado correctamente.")

    # Recuento rápido de labels, para ver qué subtipos de ataque aparecen.
    df_labels = pd.read_csv(OUTPUT_PATH, usecols=["Label"])
    print("\nRecuento de Label:")
    print(df_labels["Label"].value_counts())


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: python filter_track2_columns.py <ruta_al_thursday_csv_completo>")
        sys.exit(1)
    main(sys.argv[1])
