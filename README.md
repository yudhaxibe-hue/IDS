# Explainable Adaptive AI-Based Intrusion Detection System (IDS)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform: macOS & Windows](https://img.shields.io/badge/Platform-macOS%20%7C%20Windows-brightgreen.svg)]()
[![Python: 3.9+](https://img.shields.io/badge/Python-3.9%2B-blue.svg)]()
[![UI: pywebview + Browser](https://img.shields.io/badge/UI-Desktop%20%7C%20Safari%2FChrome-orange.svg)]()
[![Privacy: 100% Local](https://img.shields.io/badge/Privacy-100%25%20Local%20%7C%20No%20Cloud-success.svg)]()
[![GitHub release](https://img.shields.io/github/v/release/yudhaxibe-hue/IDS?include_prereleases&color=success&label=Latest%20Release)](https://github.com/yudhaxibe-hue/IDS/releases/latest)

An academic Master of Engineering prototype combining **Standardized Machine Learning Intrusion Detection**, **Explainable AI (SHAP)**, and **Statistical Concept Drift Surveillance** into a privacy-preserving desktop application for macOS and Windows.

---

# 💾 INSTALLATION & 1-CLICK QUICK RUN

> ### 🎓 For Evaluators, Professors & Quick Testing (Zero Setup Required)
> **You do NOT need to clone this repository, use the terminal, or configure Python to run this project.**
> Simply click the download button for your operating system below, open your Downloads folder, and double-click to launch!

| Operating System | Direct 1-Click Download | How to Run (2 Simple Clicks) |
| :--- | :--- | :--- |
| **🪟 Windows 10 / 11** | [**📥 Click Here to Download for Windows (.zip)**](https://github.com/yudhaxibe-hue/IDS/releases/download/v1.0.0/ExplainableAdaptiveIDS-Windows-unsigned.zip) | **1.** Unzip the downloaded file.<br>**2.** Double-click **`ExplainableAdaptiveIDS.exe`**.<br>*The app opens immediately in its own clean application window!* |
| **🍎 macOS (Apple Silicon & Intel)** | [**📥 Click Here to Download for macOS (.zip)**](https://github.com/yudhaxibe-hue/IDS/releases/download/v1.0.0/ExplainableAdaptiveIDS-macOS-unsigned.zip) | **1.** Unzip the downloaded file.<br>**2.** Double-click **`ExplainableAdaptiveIDS.app`**.<br>*(On first launch, right-click and choose "Open" to approve the unsigned research build).* |
| **📦 GitHub Releases Hub** | [**🔗 View All Releases & Checksums**](https://github.com/yudhaxibe-hue/IDS/releases/latest) | Official release portal with SHA-256 verification hashes and release notes. |

---

### 📂 Alternative: Running from the GitHub Repository Folder
If you downloaded or cloned the source code directly:
- **On Windows**: Double-click **`Run_IDS_Windows.bat`** in File Explorer.
- **On macOS**: Double-click **`Run_IDS_Mac.command`** in Finder.

The launcher handles everything automatically: it verifies your environment, prepares dependencies, checks the baseline machine learning model, and opens the application window. If native desktop rendering is unavailable on the machine, it automatically and safely falls back to opening in your default web browser (Safari / Google Chrome / Microsoft Edge) with zero login required.

---

## ⏱️ 60-Second Demonstration Guide (How to Evaluate & Showcase)

Follow these simple steps to demonstrate all core capabilities in under a minute:

1. **Launch**: Double-click `ExplainableAdaptiveIDS.exe` (or `Run_IDS_Windows.bat` on Windows / `Run_IDS_Mac.command` on macOS). The **System Overview** displays 0 flows and a clean status badge.
2. **Start Monitoring**: Click the **Live Monitoring** tab on the left sidebar.
   - Select **Demo / Offline Replay Mode** (safe, reproducible, requires zero root/admin permissions).
   - Click **Start Capture**.
3. **Observe Flow Classification**:
   - Return to the **Overview** or stay on **Live Monitoring**.
   - Watch benign traffic (HTTP, DNS, TLS) increment the **Normal Traffic** counter.
   - Watch simulated attack bursts (DoS/DDoS, Portscan, Brute Force) get detected and increment **Threat Alerts** with exact confidence scores.
4. **Inspect Explainable AI (SHAP)**:
   - Click the **Threat Alerts** tab.
   - Click the **Explain** button next to any flagged event (e.g. DoS or Portscan).
   - On the **Explainability (XAI)** tab, examine the interactive SHAP feature attribution chart and the deterministic plain-English explanation detailing *why* the traffic was flagged.
5. **Surveil Concept Drift**:
   - Switch to the **Drift & Adaptation** tab to review two-sample Kolmogorov-Smirnov distribution distance metrics and inspect the audited model adaptation registry.
6. **Generate Audit Reports**:
   - Switch to the **Export Reports** tab and click **Export Events to CSV** or **Print Report Summary** to generate complete evaluation documentation.

---

## 1. Overview & Core Mission

Modern cyberattacks continuously evolve, making black-box intrusion detection systems inadequate and difficult to trust. This system provides a practical, lightweight, and transparent IDS that:
1. **Detects & Classifies Threats**: Converts network traffic into standardized bidirectional network flow statistics and classifies traffic as Normal vs. Malicious with attack category classification (DoS/DDoS, Portscan, Brute Force, Web Attacks).
2. **Explains Predictions (XAI)**: Generates human-understandable explanations for every alert using SHAP (SHapley Additive exPlanations) and deterministic plain-language summaries detailing why a specific flow was flagged.
3. **Monitors & Adapts to Threat Drift**: Monitors live traffic for distribution shifts (concept drift) using statistical distance metrics, providing a gated, audited candidate-model evaluation and rollback mechanism without unverified blind self-training.
4. **Operates 100% Locally**: Zero paid cloud AI APIs, zero external telemetry, zero unauthenticated endpoints. Raw packet payloads are never stored or transmitted.

---

## 2. Key Features

- **Dedicated Desktop Interface**: Powered by `pywebview` with a clean, responsive HTML5/CSS3/Vanilla JS frontend. Includes automatic browser fallback (Safari/Chrome/Edge) if native webview runtime is unavailable.
- **Dual Monitoring Modes**:
  - **Offline Replay / Demo Mode**: Stream pre-recorded network flow traces and attack patterns without requiring root/administrator permissions.
  - **Live Capture**: Real-time packet capture via Scapy (BPF on macOS, Npcap on Windows) with graceful permission detection and guidance.
- **Loopback API Security**: The FastAPI backend binds strictly to `127.0.0.1` on an ephemeral port with per-session token authentication (`X-Session-Token`).
- **Local Persistence & Reporting**: SQLite database in WAL mode tracking alert history, drift logs, and model versions, with one-click export to CSV and formatted reports.

---

## 3. Technology Stack

- **Desktop Shell**: `pywebview` (with automatic browser fallback)
- **Backend API**: Python 3.9+, FastAPI, Uvicorn
- **Frontend**: HTML5, CSS3, Vanilla JavaScript (Zero Node.js / React build requirements)
- **Machine Learning**: Scikit-learn, Pandas, NumPy, Joblib
- **Explainable AI**: SHAP (`TreeExplainer`)
- **Packet & Flow Ingestion**: Scapy, Bidirectional Flow Aggregator
- **Persistence**: SQLite (Local loopback only, WAL mode)
- **Packaging**: PyInstaller, GitHub Actions (macOS & Windows runners)

---

## 4. Repository Structure

```
Explainable-Adaptive-IDS/
├── Run_IDS_Mac.command       # 🍎 1-Click launcher for macOS Finder
├── Run_IDS_Windows.bat       # 🪟 1-Click launcher for Windows File Explorer
├── app/                      # Application launcher, desktop shell & lifecycle
├── backend/                  # FastAPI server, REST routes, services & SQLite DB
├── core/                     # Preprocessing, ML detection, classification, XAI & adaptation
├── monitoring/               # Packet capture (macOS/Windows) & flow processing
├── models/               # Training scripts, evaluation notebooks & serialized models
├── datasets/                 # Dataset ingestion managers & sample records
├── packaging/                # PyInstaller spec files & installer builders
├── tests/                    # Unit, integration, ML, and packaging tests
├── documentation/            # Detailed academic reports, user manual, developer guide
├── requirements.txt          # Pinned Python dependencies
├── ARCHITECTURE.md           # Detailed technical architecture specification
├── PROJECT_STATUS.md         # Active milestone tracker and roadmap
├── DEVELOPMENT_LOG.md        # Chronological changelog and test results
└── TEST_PLAN.md              # Comprehensive verification and acceptance plan
```

---

## 5. Advanced Development & Testing

### Manual Virtual Environment Setup
```bash
# Clone the repository
git clone https://github.com/yudhaxibe-hue/IDS.git
cd Explainable-Adaptive-IDS

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Launch desktop application in development mode
python -m app.launcher

# Or launch directly in default browser:
python -m app.launcher --browser
```

### Running Test Suite
```bash
pytest tests/ -v
```

---

## 6. Project Documentation Links

- [User Manual & Operator Guide](documentation/USER_MANUAL.md)
- [System Architecture](ARCHITECTURE.md)
- [Dataset & Model Card](documentation/DATASET_AND_MODEL_CARD.md)
- [Privacy & Security Specification](documentation/PRIVACY_AND_SECURITY.md)
- [Ethical Scope & Known Limitations](documentation/KNOWN_LIMITATIONS.md)
- [Project Status & Roadmap](PROJECT_STATUS.md)
- [Development Log](DEVELOPMENT_LOG.md)
- [System Test Plan](TEST_PLAN.md)

---

## 7. Ethical Scope & Honest Limitations

1. **Host-Observable Traffic**: Monitors traffic visible to the host's local network interface. Does not claim to passively inspect unrelated network segments without a network TAP, port mirror, or gateway placement.
2. **Detection-Only (IDS, not IPS)**: Logs, classifies, and explains threats. Does not actively alter routing tables, inject TCP resets, or modify system firewall rules.
3. **No Certainty Claims**: Outputs calibrated confidence scores and probabilities. Explanations indicate feature contributions, not absolute causal proof.
