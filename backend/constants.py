from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
MODEL_DIR = ROOT / "models"
DB_PATH = DATA_DIR / "threat_detection.db"

THREAT_CLASSES = (
    "DDoS",
    "Botnet C2 Beaconing",
    "DGA / DNS Tunnelling",
    "Encrypted Malware",
    "Port Scan",
    "Data Exfiltration",
)

KNOWN_BAD_JA3 = {
    "6734f37431670b3ab4292b8f60f29984": "TrickBot",
    "4d7a28d6f2263ed61de88ca66eb011e3": "Emotet",
    "e7d705a3286e19ea42f587b344ee6865": "Example TLS malware",
}

REFERENCE_WORDS = {
    "api", "auth", "cdn", "cloud", "config", "data", "docs", "email", "gateway",
    "internal", "login", "mail", "metrics", "service", "status", "update", "vpn", "www",
}
