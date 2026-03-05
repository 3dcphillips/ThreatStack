import os
import requests
from dotenv import load_dotenv

load_dotenv()

ABUSEIPDB_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"

def check_ip(ip: str, max_age_days: int = 90) -> dict:
    key = os.getenv("ABUSEIPDB_API_KEY")
    if not key:
        raise RuntimeError("ABUSEIPDB_API_KEY not set. Check your .env file.")

    headers = {
        "Key": key.strip(),
        "Accept": "application/json",
        "User-Agent": "ThreatStack/0.1 (+local-dev)"
    }
    params = {
        "ipAddress": ip.strip(),
        "maxAgeInDays": max_age_days,
        "verbose": True,
    }

    r = requests.get(ABUSEIPDB_CHECK_URL, headers=headers, params=params, timeout=30)

    # Better error message than a raw traceback
    if r.status_code == 401:
        raise RuntimeError(
            "AbuseIPDB returned 401 Unauthorized. "
            "Your API key is missing, incorrect, or not active."
        )

    r.raise_for_status()
    return r.json().get("data", {})