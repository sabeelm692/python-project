"""Simple script to run the CVE ETL pipeline from the terminal."""

import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.pipeline import run_pipeline


def main():
    print("==================================================")
    print("🚀 Running CVE ETL Pipeline (Student Edition)")
    print("==================================================")

    # Fetch 50 records by default
    result = run_pipeline(max_records=50)

    print("\n==================================================")
    print("✅ Pipeline Finished!")
    print(f"  • Before Run Count: {result['initial_count']}")
    print(f"  • Records Fetched:  {result['fetched']}")
    print(f"  • Newly Inserted:   {result['inserted']}")
    print(f"  • Existing Updated: {result['updated']}")
    print(f"  • After Run Count:  {result['final_count']}")
    print(f"  • Time Taken:       {result['time_taken']} seconds")
    print("==================================================")


if __name__ == "__main__":
    main()
