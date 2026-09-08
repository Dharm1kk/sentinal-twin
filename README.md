# Sentinel — Passive Read-Only Cyber Threat Detection & Anomaly Platform

[![Platform](https://img.shields.io/badge/Platform-Sentinel-blue.svg)](#)
[![Design Principle](https://img.shields.io/badge/Mode-Passive_Read--Only_Diode-purple.svg)](#)
[![Integrity](https://img.shields.io/badge/Alert_Integrity-SHA--256_Hash_Chain_Ledger-emerald.svg)](#)
[![Stack](https://img.shields.io/badge/Stack-FastAPI_•_React_•_ECharts_•_XGBoost_•_IsolationForest-orange.svg)](#)

> **Sentinel** is an enterprise, passive read-only cyber threat detection and anomaly platform built for critical-infrastructure enclaves behind hardware data diodes. It transforms unidirectional network observations into behavioral features, evaluates competing threat hypotheses, learns host-specific baselines, evaluates temporal sequences via GRU recurrence, anchors alerts into an immutable SHA-256 blockchain ledger, and produces plain-English forensic explanations with a dynamic 0–100 Network Security Score.

---

## 🚀 Key Innovations & Architectural Pillars

1. **Passive Unidirectional Diode Compliance**:
   - Strictly **read-only** ingest pipeline.
   - Zero return path, zero handshakes, zero payload decryption.
2. **Two-Stage Machine Learning Pipeline (IF Baseline → Supervised XGBoost)**:
   - **Stage 1 (Unsupervised Anomaly Boundary)**: Isolation Forest trains exclusively on clean benign enclave traffic (`X_benign`, 5,000 flows) to determine normal operational boundaries without contaminated attack data.
   - **Stage 2 (Supervised Specialist Classification)**: 7 threat specialist models (DDoS, C2 Beaconing, DGA, DNS Tunneling, Reconnaissance, Encrypted Malware, Data Exfiltration) train on ground-truth labeled samples.
   - **Performance**: F1 = 1.000, ROC-AUC = 1.000 across all 7 threat specialists.
3. **Cryptographic SHA-256 Alert Hash Chain / Blockchain Ledger**:
   - Every alert is cryptographically hashed with SHA-256 and chained to the previous block hash (`index`, `alert_id`, `timestamp`, `host`, `threat_type`, `risk_score`, `prev_hash`, `details_summary`).
   - Guarantees tamper-evident alert integrity, verified live via `verify_chain()` and `verify_alert(alert_id)`.
4. **0–100 Network Security Score & Network-Wide Alert**:
   - Measures enclave posture in real-time based on incident severity, risk, and density.
   - Automatically triggers a high-priority **Network-Wide Critical Alert Banner** across the console when the security score drops below 50.
5. **GRU Sequential Threat Pattern Detector**:
   - Recurrent sequential evaluation over consecutive temporal feature windows ($T \times 34$) to detect multi-step attack escalation.
6. **Chronological Replay Controller**:
   - Step through sequential flow windows with Play, Step, and Reset timeline controls (`[ ▶ Start Replay ]`, `[ ⏭ Step Window ]`, `[ 🔄 Reset ]`) to observe live escalation on the dashboard.
7. **Deep Forensic Explainability ("Why This Alert Fired")**:
   - Plain-English root cause, observed feature deviations vs baseline rules, differential diagnosis (ruling out competing hypotheses), and recommended containment checklists.
8. **Production Light SOC Dashboard**:
   - Modern, high-contrast light enterprise theme (`bg-slate-50`, card surfaces `bg-white border-slate-200`, Apache ECharts visualizations, and responsive navigation).

---

## 📂 Project Structure

```
sentinel/
├── backend/
│   ├── api/routes.py               # REST API & WebSocket endpoints (Alerts, Datasets, Replay, Ledger)
│   ├── security/                   # SHA-256 Alert Hash Chain / Blockchain Ledger
│   │   ├── blockchain_ledger.py    # AlertBlock & BlockchainAlertLedger implementation
│   │   └── __init__.py
│   ├── ml/                         # Dataset Generation & GRU Sequence Detector
│   │   ├── dataset_generator.py    # 8-Class synthetic dataset generator (10,800 rows)
│   │   ├── gru_detector.py         # Vectorized GRU sequential threat pattern detector
│   │   └── __init__.py
│   ├── features/                   # Deterministic 34-feature extraction
│   ├── baselines/host_baseline.py  # Rolling Median, MAD, Robust Z, EWMA, CUSUM
│   ├── detectors/                  # 7 Specialist models + Isolation Forest novelty detector
│   ├── fusion/evidence_fusion.py   # Competing hypotheses & Anti-Argmax principle
│   ├── temporal/temporal_engine.py # Exponential confidence decay & calibration
│   ├── graph/evidence_graph.py     # NetworkX evidence graph & campaign correlation
│   ├── risk/risk_engine.py         # 0-100 Risk Engine & Network Security Score calculation
│   ├── explainability/explainer.py # Grounded incident narratives & forensic explanations
│   ├── schemas/alert_schema.py     # Standardized Alert JSON schema (includes SHA-256 hashes)
│   ├── db/models.py                # SQLite database models (AlertRecord, FlowRecord, etc.)
│   └── main.py                     # FastAPI application entrypoint
├── ml/
│   ├── training/train_specialists.py # Two-Stage IF + XGBoost training pipeline
│   ├── models/                     # Saved .joblib model artifacts
│   └── evaluation/metrics_report.json # Specialist evaluation metrics
├── frontend/                       # React 18 + TypeScript + Vite + Tailwind CSS + Apache ECharts
│   ├── src/components/layout/      # Header (Network-wide banner, Security score), Sidebar
│   ├── src/components/views/       # OverviewTab (Replay Controller), InvestigationsWorkspace (Ledger tab), etc.
│   ├── src/charts/                 # ECharts threat distribution, evidence graph, confidence curve
│   ├── src/api/client.ts           # Frontend API client
│   └── src/App.tsx                 # Main application shell
├── data/                           # Dataset storage (CSV datasets)
├── tests/                          # Automated unit and integration tests
├── DECISIONS.md                    # Architectural decisions, prompts followed, and rationale
└── README.md                       # Documentation and run instructions
```

---

## ⚡ Quick Start: Running Sentinel

### 1. Prerequisites
- **Python 3.11+** installed and available on PATH
- **Node.js 18+** and **npm** installed

---

### 2. Backend Setup & Startup

Open a terminal (PowerShell or Command Prompt) in the project root:

```powershell
# Navigate to the project root
cd c:\Users\Dhairya\Desktop\ARGUS

# (Optional) Activate your Python virtual environment if you use one:
# .\venv\Scripts\Activate.ps1

# Install Python dependencies (if not already installed)
pip install fastapi uvicorn scapy pandas numpy scikit-learn xgboost networkx sqlalchemy pydantic joblib

# Run all 12 automated unit tests to verify the pipeline
python -m unittest discover tests

# Start the Sentinel FastAPI backend
python backend/main.py
```
> The backend server starts on **`http://localhost:8000`**.  
> Interactive Swagger API documentation is available at **`http://localhost:8000/docs`**.

---

### 3. Frontend Setup & Startup

Open a second terminal:

```powershell
# Navigate to the frontend directory
cd c:\Users\Dhairya\Desktop\ARGUS\frontend

# Install frontend dependencies (if not already installed)
npm install

# Verify production build passes cleanly
npm run build

# Start the Vite development server
npm run dev
```
> Open your browser at **`http://localhost:5173`** to access the Sentinel SOC console.

---

### 4. Running the Complete Workflow via UI

1. **Train / Load the Models & Dataset**:
   - In the sidebar, click **"Dataset & Training"**.
   - Click **"Use Generated Dataset (11,400 Rows)"** (or upload your own CSV).
   - Click **"Start Training"** to execute the two-stage pipeline (Isolation Forest baseline fitting followed by XGBoost specialist training).
   - Once trained, click **"Analyze in Console"** to run full forensic scanning across 8 threat classes and zero-day novel anomalies.
2. **Review Security Posture in Overview**:
   - In the sidebar, click **"Overview"**.
   - Inspect the **Network Security Score (0–100)** KPI card and the **SHA-256 Ledger Block Count**.
   - If score < 50, notice the red **Network-Wide Critical Alert Banner** across the top.
   - Use the **Interactive Attack Timeline Graph & Scrubber** to play, pause, step through events, or scrub across the full attack timeline.
3. **Inspect Alert Integrity & Deep Forensics**:
   - Click **"Inspect"** on any alert row to enter **Alert Triage**.
   - View the plain-English explanation, feature deviations, and differential diagnosis.
   - Click the **"SHA-256 Ledger"** sub-tab to inspect the cryptographic block index, alert hash, previous block hash, and live tamper-free verification badge.
