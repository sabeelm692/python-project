"""Load module: Stores cleaned data in a SQL database using SQLAlchemy."""

from datetime import datetime
from pathlib import Path
import pandas as pd
from sqlalchemy import (
    Column,
    DateTime,
    Float,
    Integer,
    String,
    Text,
    create_engine,
    desc,
    func,
    select,
)
from sqlalchemy.orm import declarative_base, sessionmaker

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DB_DIR = PROJECT_ROOT / "db"
DB_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DB_DIR / "cve_database.db"
DB_URL = f"sqlite:///{DB_PATH}"

engine = create_engine(DB_URL, echo=False)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()


class CVE(Base):
    """Table to store CVE vulnerability records."""

    __tablename__ = "cves"

    cve_id = Column(String(50), primary_key=True, index=True)
    published_date = Column(String(20))
    last_modified_date = Column(String(20))
    vuln_status = Column(String(50))
    description = Column(Text)
    cvss_version = Column(String(20))
    base_score = Column(Float, nullable=True)
    severity = Column(String(30))
    attack_vector = Column(String(50))
    cwe_id = Column(String(100))
    reference_count = Column(Integer, default=0)
    saved_at = Column(DateTime, default=datetime.now)


class IngestionLog(Base):
    """Table to log each ETL run for auditing and grading."""

    __tablename__ = "ingestion_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.now)
    records_fetched = Column(Integer, default=0)
    records_inserted = Column(Integer, default=0)
    records_updated = Column(Integer, default=0)
    status = Column(String(30), default="SUCCESS")


def init_db():
    """Creates database tables if they don't already exist."""
    Base.metadata.create_all(bind=engine)


def get_cve_count():
    """Returns the total number of records currently in the database."""
    init_db()
    with SessionLocal() as session:
        return session.query(func.count(CVE.cve_id)).scalar() or 0


def save_cves_to_db(df):
    """Saves or updates DataFrame records in the SQL database."""
    init_db()
    if df.empty:
        return 0, 0

    inserted_count = 0
    updated_count = 0
    records = df.to_dict(orient="records")

    with SessionLocal() as session:
        for r in records:
            cid = r.get("cve_id")
            existing = session.query(CVE).filter_by(cve_id=cid).first()

            if existing:
                # Update existing record
                existing.published_date = r.get("published_date")
                existing.last_modified_date = r.get("last_modified_date")
                existing.vuln_status = r.get("vuln_status")
                existing.description = r.get("description")
                existing.cvss_version = r.get("cvss_version")
                existing.base_score = r.get("base_score")
                existing.severity = r.get("severity")
                existing.attack_vector = r.get("attack_vector")
                existing.cwe_id = r.get("cwe_id")
                existing.reference_count = r.get("reference_count", 0)
                existing.saved_at = datetime.now()
                updated_count += 1
            else:
                # Insert new record
                new_cve = CVE(
                    cve_id=cid,
                    published_date=r.get("published_date"),
                    last_modified_date=r.get("last_modified_date"),
                    vuln_status=r.get("vuln_status"),
                    description=r.get("description"),
                    cvss_version=r.get("cvss_version"),
                    base_score=r.get("base_score"),
                    severity=r.get("severity"),
                    attack_vector=r.get("attack_vector"),
                    cwe_id=r.get("cwe_id"),
                    reference_count=r.get("reference_count", 0),
                )
                session.add(new_cve)
                inserted_count += 1

        session.commit()

    return inserted_count, updated_count


def log_ingestion(fetched, inserted, updated, status="SUCCESS"):
    """Adds an entry to the ingestion_logs table."""
    init_db()
    with SessionLocal() as session:
        log = IngestionLog(
            timestamp=datetime.now(),
            records_fetched=fetched,
            records_inserted=inserted,
            records_updated=updated,
            status=status,
        )
        session.add(log)
        session.commit()


def load_all_cves_from_db():
    """Reads all CVE records into a pandas DataFrame."""
    init_db()
    with SessionLocal() as session:
        rows = session.query(CVE).order_by(desc(CVE.published_date)).all()
        data = [
            {
                "cve_id": r.cve_id,
                "published_date": r.published_date,
                "last_modified_date": r.last_modified_date,
                "vuln_status": r.vuln_status,
                "description": r.description,
                "cvss_version": r.cvss_version,
                "base_score": r.base_score,
                "severity": r.severity,
                "attack_vector": r.attack_vector,
                "cwe_id": r.cwe_id,
                "reference_count": r.reference_count,
            }
            for r in rows
        ]
        return pd.DataFrame(data)


def load_ingestion_logs_from_db():
    """Reads ingestion history into a pandas DataFrame."""
    init_db()
    with SessionLocal() as session:
        rows = session.query(IngestionLog).order_by(desc(IngestionLog.id)).limit(15).all()
        data = [
            {
                "Run ID": r.id,
                "Timestamp": r.timestamp.strftime("%Y-%m-%d %H:%M:%S") if r.timestamp else "",
                "Fetched": r.records_fetched,
                "Inserted": r.records_inserted,
                "Updated": r.records_updated,
                "Status": r.status,
            }
            for r in rows
        ]
        return pd.DataFrame(data)
