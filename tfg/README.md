# Datos y scripts de evaluación del TFG

Este repositorio contiene los scripts, los datasets construidos y los resultados de los tres experimentos (Track 1, 2 y 3) del TFG «Triaje automatizado de alertas de seguridad con ML, enriquecimiento y correlación en grafo».

## Licencia

El código se distribuye bajo licencia MIT (ver `LICENSE` en la raíz). La licencia MIT cubre únicamente el código. Los datos derivados de terceros conservan las condiciones de uso de sus autores, indicadas más abajo.

## Estructura

- `track1/`: 58 IOCs etiquetados (hashes maliciosos de MalwareBazaar y dominios benignos de Tranco), evaluación de la heurística y de los modelos de ML.
- `track2/`: 28 Alertas construidas a partir de CICIDS2017 (jueves, ataques web) y correlación en grafo.
- `track3/`: 10 IOCs de la familia Mirai (hashes y direcciones IP de mando y control) para validar el sistema completo.

## Datos de terceros

| Fuente | Uso | Dónde conseguirla |
|---|---|---|
| MalwareBazaar (abuse.ch) | Hashes maliciosos del Track 1 (respuesta sin procesar en `track1/track1_malwarebazaar_raw.json`) | Dónde obtenerla: https://bazaar.abuse.ch (la API requiere una Auth-Key gratuita) |
| ThreatFox (abuse.ch) | IPs de mando y control del Track 3 | Dónde obtenerla: https://threatfox.abuse.ch |
| Tranco | Dominios benignos de referencia del Track 1 | Dónde obtenerla: https://tranco-list.eu |
| CICIDS2017, versión corregida | Eventos de red del Track 2 | Dónde obtenerla: Fuente primaria: https://github.com/GintsEngelen/CNS2022_Code. Mirror usado en este trabajo: https://www.kaggle.com/datasets/ernie55ernie/improved-cicids2017-and-csecicids2018  |

Consulte las condiciones de uso publicadas por cada proveedor antes de redistribuir sus datos. La inclusión de datos derivados en este repositorio no implica autorización para redistribuirlos.

## Fichero no incluido en el repositorio

`track2/thursday.csv` (≈181 MB, CICIDS2017 corregido) y `track2/thursday_filtered.csv` (≈42 MB) no se incluyen: superan el límite de tamaño por archivo de GitHub y son datos de terceros. Para reproducir el Track 2:

1. Descargue `thursday.csv` de la versión corregida de CICIDS2017 y colóquelo en `track2/`.
2. `python filter_track2_columns.py thursday.csv`
3. `python build_track2.py thursday_filtered.csv`

## Reproducibilidad

El Track 1 se construye con `build_track1.py`, que consulta MalwareBazaar en el momento de la ejecución. Una ejecución posterior puede producir muestras distintas. Por ello, se conservan la respuesta sin procesar y los resultados de la ejecución documentada. Además, las puntuaciones dependen del estado de VirusTotal en el momento de la consulta y pueden variar entre ejecuciones..