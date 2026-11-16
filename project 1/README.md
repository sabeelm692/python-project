# 🛡️ CVE Vulnerability ETL & EDA Platform
**Course:** Programming for AI — Project 1 (ETL + EDA Pipeline)  
**Total Marks:** 10 Marks

An automated Data Engineering pipeline and interactive dashboard that collects live security vulnerabilities from the **NIST National Vulnerability Database (NVD API v2.0)**, validates them with **Pydantic**, stores them in an **SQL Database**, and visualizes them using **Streamlit & Plotly**.

---

## 🎯 What Does This Project Do?

1. **Extract**: Automatically downloads CVE records from NIST's REST API.
2. **Transform & Validate**: Cleans messy data, selects English descriptions, calculates CVSS scores, and validates data types using **Pydantic**.
3. **Load**: Saves records into an SQL database (`db/cve_database.db`) using **SQLAlchemy** with duplicate prevention (upsert) and an audit log table.
4. **EDA & Visualizations**: An interactive web dashboard with:
   * **KPIs**: Total CVEs, Critical, High, Medium, and Average CVSS Score.
   * **Severity Breakdown**: Interactive donut chart.
   * **CVSS Score Histogram**: Distribution of vulnerability severity scores.
   * **Top 10 Weaknesses (CWE)**: Most common exploit types (e.g. CWE-126, CWE-190).
   * **Attack Vectors**: How attacks occur (Network vs Local).
   * **Search & Filter Table**: Search by CVE ID, keyword, or score slider.
   * **Live Pipeline Trigger**: Button to pull live data with a dynamic progress bar.

---

## 💻 How to Run on Your Laptop (Quick Setup)

You do **NOT** need Docker to run this project! You can run it with standard Python in 3 simple steps:

### For Windows:
1. Open **Command Prompt** or **PowerShell** inside the unzipped folder:
   ```cmd
   cd "project 1"
   ```
2. Create and activate a virtual environment:
   ```cmd
   python -m venv venv
   venv\Scripts\activate
   ```
3. Install dependencies:
   ```cmd
   pip install -r requirements.txt
   ```
4. Start the dashboard:
   ```cmd
   streamlit run app/streamlit_app.py
   ```
   👉 It will automatically open your browser at **`http://localhost:8501`**!

---

### For Mac / Linux:
1. Open **Terminal** inside the folder:
   ```bash
   cd "project 1"
   ```
2. Create and activate virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Start the dashboard:
   ```bash
   streamlit run app/streamlit_app.py
   ```
   👉 Open your browser at **`http://localhost:8501`**.

---

## 🐳 Optional: Run with Docker

If you or your teacher prefer using Docker, you don't even need to install Python:

```bash
docker compose up --build
```
Open **`http://localhost:8501`** in your browser.

---

## 📁 Project Structure

```
project 1/
├── app/
│   └── streamlit_app.py        # Web dashboard & interactive charts
├── data/
│   ├── raw/                    # Raw JSON files saved per API response
│   └── clean/                  # Cleaned CSV backups
├── db/
│   └── cve_database.db         # Pre-loaded SQLite database
├── src/
│   ├── config.py               # API endpoints and paths
│   ├── extract.py              # NIST API fetcher with pagination
│   ├── schema.py               # Pydantic data validation model
│   ├── transform.py            # Data cleaning and normalization
│   ├── load.py                 # SQLAlchemy database storage and audit logs
│   └── pipeline.py             # Orchestrator (Extract -> Transform -> Load)
├── run_pipeline.py             # Command-line runner
├── Dockerfile                  # Container instructions
├── docker-compose.yml          # Docker setup
├── requirements.txt            # Python libraries
└── README.md                   # Instructions
```

---

## 🎓 Teacher Live Demo Guide

To show your teacher that the pipeline is **live and dynamic** (not static):
1. Note the current number of CVEs shown in the left sidebar (e.g. `130`).
2. In the left sidebar, choose **Records to Fetch** (e.g. `20`) and select **Date Range**.
3. Click **"▶ Run ETL Pipeline"**.
4. Show your teacher:
   * The live progress bar during extraction and Pydantic validation.
   * The stored count increasing.
   * Go to **"⚡ Live Pipeline Logs"** tab to show the new run timestamp and record count recorded in the database audit table!
