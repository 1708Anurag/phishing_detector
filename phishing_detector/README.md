# PhishGuard — Phishing Email Detection System

A major project (Python · Flask · SQLAlchemy · pure-Python Naive Bayes) that detects
phishing emails using a combination of rule-based heuristics and a machine
learning text classifier. Built for a 5-member team.

## Features

- User registration & login (Flask-Login, hashed passwords)
- Paste any email (sender, subject, body) and get an instant risk score (0-100)
- Two detection layers combined into one verdict:
  - **Heuristics** — urgency language, credential requests, suspicious
    links (raw IPs, risky TLDs, brand-lookalike domains), sender spoofing
  - **ML classifier** — a Naive Bayes text classifier trained on labeled
    phishing/legitimate email samples, implemented in pure Python (no
    numpy/scipy/scikit-learn) so it runs even on locked-down machines
    that block compiled DLLs via Application Control / WDAC policies
- Per-user scan history stored in a SQLite database (SQLAlchemy ORM)
- Dashboard with live stats and a paginated history table
- Explainable results — every verdict lists the exact signals that triggered it

## Tech stack

| Layer      | Technology                          |
|------------|--------------------------------------|
| Backend    | Python 3.10+, Flask, Flask-Login     |
| Database   | SQLite via Flask-SQLAlchemy          |
| ML         | Pure-Python Naive Bayes (standard library only, no numpy/scipy) |
| Frontend   | Jinja2 templates, vanilla CSS/JS     |

## Project structure

```
phishing_detector/
├── app.py                 # App factory, run entry point
├── config.py               # Configuration (DB path, secret key, etc.)
├── extensions.py           # Shared db / login_manager instances
├── models.py                # User & ScanHistory SQLAlchemy models
├── auth.py                  # Auth blueprint (register/login/logout)
├── main.py                  # Main blueprint (dashboard/scan/history)
├── train_model.py           # Standalone script to (re)train the ML model
├── detection/
│   ├── heuristics.py        # Rule-based detection engine
│   ├── ml_model.py          # Pure-Python Naive Bayes classifier
│   ├── dataset.py           # Sample labeled training data
│   └── analyzer.py          # Combines heuristics + ML into final verdict
├── templates/                # Jinja2 HTML templates
├── static/css, static/js     # Styling & small client-side scripts
└── requirements.txt
```

## Setup instructions

1. **Create a virtual environment** (recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate      # Windows: venv\Scripts\activate
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **(Optional) Pre-train the ML model.** This happens automatically on
   first run, but you can run it manually and see the accuracy:
   ```bash
   python train_model.py
   ```

4. **Run the app:**
   ```bash
   python app.py
   ```
   The database tables and instance folder are created automatically.
   Visit **http://127.0.0.1:5000** in your browser.

5. **Try it out:** register an account, go to the Dashboard, click
   **"Load phishing sample"** to autofill a demo email, then click
   **Analyze email** to see the risk score and explanation.

## Improving this for your final submission

- Replace `detection/dataset.py` with a larger public phishing-email
  dataset (e.g. the Nazario corpus or a Kaggle phishing dataset), then
  re-run `python train_model.py`.
- Add `.eml` file upload parsing (Python's built-in `email` module) instead
  of only pasted text.
- Add an admin role that can view all users' scans for demo purposes.
- Deploy with a production WSGI server (e.g. Gunicorn) behind Nginx, and
  switch `SECRET_KEY` / `DATABASE_URL` to environment variables.

## Suggested 5-person work split

| # | Member | Responsibility | Files |
|---|--------|-----------------|-------|
| 1 | Backend/Auth | App factory, authentication, models | `app.py`, `auth.py`, `models.py`, `extensions.py` |
| 2 | Detection (rules) | Heuristic engine | `detection/heuristics.py` |
| 3 | Detection (ML) | Dataset, model training, combined scoring | `detection/ml_model.py`, `detection/dataset.py`, `detection/analyzer.py` |
| 4 | Frontend/UI | Templates, styling, UX | `templates/`, `static/` |
| 5 | QA/Docs | Testing, README, report, presentation | tests, `README.md`, slide deck |

## Disclaimer

This project is for educational purposes to demonstrate phishing-detection
concepts. It is not a production-grade email security gateway.
