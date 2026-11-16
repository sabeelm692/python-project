"""Data validation models using Pydantic.

This file ensures that every CVE record has valid data types before saving to the database.
"""

from typing import Optional
from pydantic import BaseModel, Field


class CVEItem(BaseModel):
    """Simple and clean schema for a single CVE vulnerability."""

    cve_id: str = Field(description="Unique CVE ID like CVE-2024-1234")
    published_date: Optional[str] = Field(default="Unknown", description="Publication date")
    last_modified_date: Optional[str] = Field(default="Unknown", description="Last updated date")
    vuln_status: Optional[str] = Field(default="Unknown", description="Status e.g. Analyzed or Modified")
    description: Optional[str] = Field(default="No description available", description="English summary")
    cvss_version: Optional[str] = Field(default="N/A", description="CVSS version like 3.1 or 2.0")
    base_score: Optional[float] = Field(default=None, ge=0.0, le=10.0, description="Score between 0.0 and 10.0")
    severity: Optional[str] = Field(default="UNKNOWN", description="LOW, MEDIUM, HIGH, or CRITICAL")
    attack_vector: Optional[str] = Field(default="UNKNOWN", description="e.g. NETWORK, LOCAL")
    cwe_id: Optional[str] = Field(default="None", description="Weakness type like CWE-79 or CWE-89")
    reference_count: int = Field(default=0, ge=0, description="Number of advisory links")
