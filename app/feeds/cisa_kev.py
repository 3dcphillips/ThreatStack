import requests

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

def fetch_kev():
    r = requests.get(CISA_KEV_URL, timeout=30)
    r.raise_for_status()
    return r.json().get("vulnerabilities", [])