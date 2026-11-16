"""Extract module: Downloads vulnerability data from the NIST NVD API."""

import json
import os
import time
from datetime import datetime
from pathlib import Path
import requests

# Base paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent
RAW_DATA_DIR = PROJECT_ROOT / "data" / "raw"
RAW_DATA_DIR.mkdir(parents=True, exist_ok=True)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def fetch_cves_from_api(start_date=None, end_date=None, max_records=50, page_size=50, progress_callback=None):
    """Fetches CVE records from the NIST API with pagination and rate limits."""
    headers = {"User-Agent": "CVE-ETL-Student-Project/1.0"}

    # If the user has an NVD API key set as an environment variable
    api_key = os.getenv("NVD_API_KEY", "").strip()
    if api_key:
        headers["apiKey"] = api_key

    delay = 0.6 if api_key else 6.0
    all_records = []
    start_index = 0

    print(f"[*] Starting extraction: fetching up to {max_records} CVEs from NIST API...")

    while len(all_records) < max_records:
        fetch_count = min(page_size, max_records - len(all_records))
        params = {
            "startIndex": start_index,
            "resultsPerPage": fetch_count,
        }

        if start_date and end_date:
            params["pubStartDate"] = start_date
            params["pubEndDate"] = end_date

        if progress_callback:
            progress_callback(len(all_records), max_records, f"Fetching records {start_index} to {start_index + fetch_count}...")

        try:
            response = requests.get(NVD_API_URL, headers=headers, params=params, timeout=30)
            response.raise_for_status()
            data = response.json()
        except Exception as e:
            print(f"[!] API request failed: {e}")
            break

        batch = data.get("vulnerabilities", [])
        if not batch:
            break

        all_records.extend(batch)
        start_index += len(batch)

        # Save raw JSON copy to data/raw/
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        raw_file = RAW_DATA_DIR / f"raw_cves_{timestamp}_batch.json"
        with open(raw_file, "w", encoding="utf-8") as f:
            json.dump(batch, f, indent=2)

        print(f"[*] Fetched {len(all_records)} / {max_records} records (Saved to {raw_file.name})")

        total_available = data.get("totalResults", 0)
        if start_index >= total_available:
            break

        if len(all_records) < max_records:
            time.sleep(delay)

    return all_records
