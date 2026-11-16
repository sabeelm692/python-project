"""Configuration settings for the CVE ETL & EDA Pipeline."""

import os
from pathlib import Path

# Paths
SRC_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SRC_DIR.parent
DATA_DIR = PROJECT_ROOT / "data"
DATA_RAW_DIR = DATA_DIR / "raw"
DATA_CLEAN_DIR = DATA_DIR / "clean"
DB_DIR = PROJECT_ROOT / "db"

# Ensure runtime directories exist
DATA_RAW_DIR.mkdir(parents=True, exist_ok=True)
DATA_CLEAN_DIR.mkdir(parents=True, exist_ok=True)
DB_DIR.mkdir(parents=True, exist_ok=True)

# NIST NVD API v2.0
NVD_API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.getenv("NVD_API_KEY", "")

# NIST limits: max 120 days per request window, max 2000 resultsPerPage
NVD_MAX_WINDOW_DAYS = 120
DEFAULT_PAGE_SIZE = 2000

# Rate limits: ~6s without key, ~0.6s with key
RATE_LIMIT_DELAY = 0.6 if NVD_API_KEY else 6.0

# Database Configuration (supports SQLite by default, or MySQL via env var)
# SQLite: sqlite:////absolute/path/to/cves.db
# MySQL:  mysql+pymysql://user:password@localhost:3306/cve_db
DEFAULT_SQLITE_URL = f"sqlite:///{DB_DIR / 'cve_database.db'}"
DATABASE_URL = os.getenv("DATABASE_URL", DEFAULT_SQLITE_URL)
