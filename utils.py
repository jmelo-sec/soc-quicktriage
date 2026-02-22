import re

def detect_ioc_type(ioc: str) -> str:
    ip_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"
    hash_pattern = r"^[A-Fa-f0-9]{32,64}$"  # MD5/SHA1/SHA256 (aprox)

    if re.match(ip_pattern, ioc):
        return "ip"
    if re.match(hash_pattern, ioc):
        return "hash"
    return "domain"