VA Report Web App
=================

Minimal Flask web UI over the existing `consolidation.py` logic.

Features
- Consolidate: upload a ZIP of CSVs or select multiple CSV files, then download `consolidated_vulnerability_report.csv`.
- Summary: upload a single CSV, then download `vulnerability_summary.csv`.
- Bootstrap-based minimal UI.

Requirements
- Python 3.10+

Setup
1. Create and (optionally) activate a virtual environment.
2. Install dependencies:

```bash
pip install -r requirements.txt
```

Run the App

```bash
export FLASK_SECRET_KEY=change-me   # optional
python app.py
```

Open `http://localhost:5000` in your browser.

Usage
- Choose the operation:
  - Consolidate: upload a `.zip` containing CSVs, or select multiple `.csv` files.
  - Summary: upload a single `.csv` file.
- Click Run; your processed CSV will download automatically.

Notes
- The backend calls `consolidation.consolidated_process` and `consolidation.summary_process` directly.
- For Consolidate, outputs may be written in the working directory; the app locates them for download.
- For Summary, the output is normalized to `vulnerability_summary.csv`.

