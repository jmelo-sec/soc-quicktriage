# scoring.py
# Fórmula de puntuación: cada fuente suma puntos según lo que detecte.
# Los pesos son arbitrarios, sin validar con datos reales - de hecho, esa 
# validación es una de las cosas que se evalúan en este TFG.

def calculate_score(vt: dict | None, abuse: dict | None, otx: dict | None):
    score = 0.0
    factors = []

    # VirusTotal: Pesa más "malicious" que "suspicious".
    if vt and "error" not in vt:
        malicious = vt.get("malicious", 0)
        suspicious = vt.get("suspicious", 0)
        if malicious:
            score += malicious * 6
            factors.append(f"VirusTotal: {malicious} Motores marcan Malicioso")
        if suspicious:
            score += suspicious * 3
            factors.append(f"VirusTotal: {suspicious} Motores marcan Sospechoso")

    # AbuseIPDB: Usamos su porcentaje de confianza tal cual, escalado por 0,7.
    if abuse and "error" not in abuse:
        confidence = abuse.get("abuseConfidenceScore", 0)
        if confidence:
            score += confidence * 0.7
            factors.append(f"AbuseIPDB: confianza {confidence}%")

    # OTX: 5 puntos por pulse, con tope de 25 puntos para evitar que esta fuente por sí sola
    # determine el veredicto.
    if otx and "error" not in otx:
        pulses = otx.get("pulse_count", 0)
        if pulses:
            score += min(pulses * 5, 25)
            factors.append(f"OTX: {pulses} pulses detectados")

    score = round(min(score, 100.0), 2)
    return score, factors

def classify(score: float) -> str:
    # Umbrales de clasificación cualitativa.
    if score < 20:
        return "LOW"
    if score < 50:
        return "MEDIUM"
    if score < 80:
        return "HIGH"
    return "CRITICAL"