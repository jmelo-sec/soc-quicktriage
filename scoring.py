def calculate_score(vt: dict | None, abuse: dict | None, otx: dict | None):
    score = 0.0
    factors = []

    if vt and "error" not in vt:
        mal = vt.get("malicious", 0)
        susp = vt.get("suspicious", 0)
        if mal:
            score += mal * 6
            factors.append(f"VirusTotal: {mal} engines flagged malicious")
        if susp:
            score += susp * 3
            factors.append(f"VirusTotal: {susp} engines flagged suspicious")

    if abuse and "error" not in abuse:
        conf = abuse.get("abuseConfidenceScore", 0)
        if conf:
            score += conf * 0.7
            factors.append(f"AbuseIPDB: confidence {conf}%")

    if otx and "error" not in otx:
        pulses = otx.get("pulse_count", 0)
        if pulses:
            score += min(pulses * 5, 25)
            factors.append(f"OTX: {pulses} pulses detected")

    score = round(min(score, 100.0), 2)
    return score, factors

def classify(score: float) -> str:
    if score < 20:
        return "LOW"
    if score < 50:
        return "MEDIUM"
    if score < 80:
        return "HIGH"
    return "CRITICAL"