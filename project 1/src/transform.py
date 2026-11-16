"""Transform module: Cleans raw API JSON and validates it using Pydantic."""

from pathlib import Path
import pandas as pd
from pydantic import ValidationError
from src.schema import CVEItem

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CLEAN_DATA_DIR = PROJECT_ROOT / "data" / "clean"
CLEAN_DATA_DIR.mkdir(parents=True, exist_ok=True)


def parse_single_cve(item):
    """Extracts required fields from one raw CVE dictionary."""
    cve = item.get("cve", {})

    # 1. CVE ID
    cve_id = cve.get("id", "Unknown")

    # 2. Dates and Status
    pub_date = cve.get("published", "")
    mod_date = cve.get("lastModified", "")
    status = cve.get("vulnStatus", "Unknown")

    # 3. English description only
    desc_en = "No description available"
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            desc_en = d.get("value", desc_en)
            break

    # 4. CVSS Score, Severity, and Attack Vector
    metrics = cve.get("metrics", {})
    cvss_ver = "N/A"
    base_score = None
    severity = "UNKNOWN"
    attack_vector = "UNKNOWN"

    # Check v3.1 first, then v3.0, then v2.0
    metric_entry = None
    if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
        metric_entry = metrics["cvssMetricV31"][0]
        cvss_ver = "3.1"
    elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
        metric_entry = metrics["cvssMetricV30"][0]
        cvss_ver = "3.0"
    elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
        metric_entry = metrics["cvssMetricV2"][0]
        cvss_ver = "2.0"

    if metric_entry:
        cvss_data = metric_entry.get("cvssData", {})
        base_score = cvss_data.get("baseScore")
        cvss_ver = cvss_data.get("version", cvss_ver)

        raw_sev = cvss_data.get("baseSeverity") or metric_entry.get("baseSeverity")
        if raw_sev:
            severity = str(raw_sev).upper()
        elif base_score is not None:
            # Fallback rating calculation if missing
            if base_score >= 9.0:
                severity = "CRITICAL"
            elif base_score >= 7.0:
                severity = "HIGH"
            elif base_score >= 4.0:
                severity = "MEDIUM"
            elif base_score > 0.0:
                severity = "LOW"

        raw_av = cvss_data.get("attackVector") or cvss_data.get("accessVector")
        if raw_av:
            attack_vector = str(raw_av).upper()

    # 5. Weakness / CWE
    cwe_id = "None"
    weaknesses = cve.get("weaknesses", [])
    if weaknesses:
        cwe_descs = weaknesses[0].get("description", [])
        if cwe_descs:
            cwe_id = cwe_descs[0].get("value", "None")

    # 6. References
    ref_count = len(cve.get("references", []))

    return {
        "cve_id": cve_id,
        "published_date": pub_date[:10] if len(pub_date) >= 10 else pub_date,
        "last_modified_date": mod_date[:10] if len(mod_date) >= 10 else mod_date,
        "vuln_status": status,
        "description": desc_en,
        "cvss_version": cvss_ver,
        "base_score": base_score,
        "severity": severity,
        "attack_vector": attack_vector,
        "cwe_id": cwe_id,
        "reference_count": ref_count,
    }


def clean_and_validate_data(raw_records):
    """Validates raw records with Pydantic and returns a pandas DataFrame."""
    clean_list = []

    for item in raw_records:
        parsed = parse_single_cve(item)
        if parsed["cve_id"] == "Unknown":
            continue

        try:
            # Validate with Pydantic
            valid_item = CVEItem(**parsed)
            clean_list.append(valid_item.model_dump())
        except ValidationError as err:
            print(f"[!] Dropped invalid record {parsed.get('cve_id')}: {err}")

    df = pd.DataFrame(clean_list)

    # Remove duplicates if any
    if not df.empty and "cve_id" in df.columns:
        df = df.drop_duplicates(subset=["cve_id"], keep="last")

    # Save clean copy to CSV
    csv_file = CLEAN_DATA_DIR / "cves.csv"
    df.to_csv(csv_file, index=False)
    print(f"[*] Cleaned {len(df)} records (Saved to {csv_file.name})")

    return df
