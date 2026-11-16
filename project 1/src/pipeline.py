"""Pipeline module: connects Extract -> Transform -> Load in one simple function."""

import time
from src.extract import fetch_cves_from_api
from src.load import get_cve_count, log_ingestion, save_cves_to_db
from src.transform import clean_and_validate_data


def run_pipeline(start_date=None, end_date=None, max_records=50, progress_callback=None):
    """Executes the complete ETL pipeline."""
    start_time = time.time()
    initial_count = get_cve_count()

    # 1. EXTRACT
    raw_records = fetch_cves_from_api(
        start_date=start_date,
        end_date=end_date,
        max_records=max_records,
        progress_callback=progress_callback,
    )

    if not raw_records:
        log_ingestion(0, 0, 0, status="EMPTY")
        return {
            "initial_count": initial_count,
            "final_count": initial_count,
            "fetched": 0,
            "inserted": 0,
            "updated": 0,
            "time_taken": round(time.time() - start_time, 2),
        }

    # 2. TRANSFORM & VALIDATE
    if progress_callback:
        progress_callback(len(raw_records), max_records, "Cleaning and validating data with Pydantic...")
    clean_df = clean_and_validate_data(raw_records)

    # 3. LOAD
    if progress_callback:
        progress_callback(len(raw_records), max_records, "Saving validated records to SQL database...")
    inserted, updated = save_cves_to_db(clean_df)

    # Log the execution
    log_ingestion(len(raw_records), inserted, updated, status="SUCCESS")

    final_count = get_cve_count()
    time_taken = round(time.time() - start_time, 2)

    return {
        "initial_count": initial_count,
        "final_count": final_count,
        "fetched": len(raw_records),
        "inserted": inserted,
        "updated": updated,
        "time_taken": time_taken,
    }
