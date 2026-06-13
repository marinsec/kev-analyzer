import json

import requests

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
LOCAL_FILE = "kev.json"


def download_kev() -> dict:
    headers = {"User-Agent": "kev-analyzer/0.1"}
    response = requests.get(KEV_URL, headers=headers, timeout=30)
    response.raise_for_status()
    data = response.json()

    with open(LOCAL_FILE, "w") as f:
        json.dump(data, f, indent=2)

    return data


def load_kev() -> dict:
    with open(LOCAL_FILE) as f:
        return json.load(f)
