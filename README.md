# Explainable Adaptive AI-Based Intrusion Detection System (IDS)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-macOS%20%7C%20Windows-brightgreen.svg)]()
[![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg)]()
[![Interface](https://img.shields.io/badge/UI-pywebview%20Native%20Desktop-orange.svg)]()

An academic Master of Engineering prototype combining **Machine Learning Intrusion Detection**, **Explainable AI (SHAP)**, and **Controlled Concept Drift Adaptation** into a single, privacy-preserving desktop application.

---

## 1. Overview & Core Mission

Modern cyberattacks continuously evolve, making black-box intrusion detection systems inadequate and difficult to trust. This system provides a practical, lightweight, and transparent IDS that:
1. **Detects & Classifies Threats**: Converts network traffic into standardized bidirectional network flow statistics and classifies traffic as Normal vs. Malicious with attack category classification (DoS/DDoS, Portscan, Brute Force, Web Attacks).
2. **Explains Predictions (XAI)**: Generates human-understandable explanations for every alert using SHAP (SHapley Additive exPlanations) and deterministic plain-language summaries detailing why a specific flow was flagged.
3. **Monitors & Adapts to Threat Drift**: Monitors live traffic for distribution shifts (concept drift) using statistical distance metrics, providing a gated, audited candidate-model evaluation and rollback mechanism without unverified blind self-training.
4. **Operates 100% Locally**: Zero paid cloud AI APIs, zero external telemetry, zero unauthenticated endpoints. Raw packet payloads are never stored or transmitted.

---

## 2. Key Features

- **Dedicated Desktop Interface**: Powered by `pywebview` with a clean, responsive HTML5/CSS3/Vanilla JS frontend. Runs in its own native desktop window without requiring an external browser tab.
- **Dual Monitoring Modes**:
  - **Live Capture**: Real-time packet capture via Scapy (BPF on macOS, Npcap on Windows) with graceful permission detection and guidance.
  - **Offline Replay / Demo Mode**: Stream pre-recorded network flow traces and attack patterns without requiring root/administrator permissions.
- **Loopback API Security**: The FastAPI backend binds strictly to `127.0.0.1` on an ephemeral port with per-session token authentication (`X-Session-Token`).
- **Local Persistence & Reporting**: SQLite database in WAL mode tracking alert history, drift logs, and model versions, with one-click export to CSV and formatted reports.

---

## 3. Technology Stack

- **Desktop Shell**: `pywebview`
- **Backend API**: Python 3.9+, FastAPI, Uvicorn
- **Frontend**: HTML5, CSS3, Vanilla JavaScript (Zero Node.js / React build requirements)
- **Machine Learning**: Scikit-learn, Pandas, NumPy, Joblib
- **Explainable AI**: SHAP (`TreeExplainer`)
- **Packet & Flow Ingestion**: Scapy, Bidirectional Flow Aggregator
- **Persistence**: SQLite (Local loopback only)
- **Packaging**: PyInstaller, GitHub Actions (macOS & Windows runners)

---

## 4. Repository Structure

```
Explainable-Adaptive-IDS/
├── app/                  # Application launcher, desktop shell & lifecycle
├── backend/              # FastAPI server, REST routes, services & SQLite DB
├── core/                 # Preprocessing, ML detection, classification, XAI & adaptation
├── monitoring/           # Packet capture (macOS/Windows) & flow processing
├── models/               # Training scripts, evaluation notebooks & serialized models
├── datasets/             # Dataset ingestion managers & sample records
├── packaging/            # PyInstaller spec files & installer builders
├── tests/                # Unit, integration, ML, and packaging tests
├── documentation/        # Detailed academic reports, user manual, developer guide
├── requirements.txt      # Pinned Python dependencies
├── ARCHITECTURE.md       # Detailed technical architecture specification
├── PROJECT_STATUS.md     # Active milestone tracker and roadmap
├── DEVELOPMENT_LOG.md    # Chronological changelog and test results
└── TEST_PLAN.md          # Comprehensive verification and acceptance plan
```

---

## 5. Quick Start (Development Mode)

### Prerequisites
- Python 3.9, 3.10, 3.11, or 3.12
- macOS (Apple Silicon or Intel) or Windows 10/11
- Git

### Setup & Run
```bash
# Clone the repository
git clone <repository-url>
cd Explainable-Adaptive-IDS

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Launch desktop application in development mode
python -m app.launcher
```

---

## 6. Project Documentation Links

- [System Architecture](ARCHITECTURE.md)
- [Project Status & Roadmap](PROJECT_STATUS.md)
- [Development Log](DEVELOPMENT_LOG.md)
- [System Test Plan](TEST_PLAN.md)

---

## 7. Ethical Scope & Honest Limitations

1. **Host-Observable Traffic**: Monitors traffic visible to the host's local network interface. Does not claim to passively inspect unrelated network segments without a network TAP, port mirror, or gateway placement.
2. **Detection-Only (IDS, not IPS)**: Logs, classifies, and explains threats. Does not actively alter routing tables, inject TCP resets, or modify system firewall rules.
3. **No Certainty Claims**: Outputs calibrated confidence scores and probabilities. Explanations indicate feature contributions, not absolute causal proof.
