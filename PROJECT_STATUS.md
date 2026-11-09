# Project Status & Milestone Tracker

**Project Title**: Explainable Adaptive AI-Based Intrusion Detection System for Changing Network Threats  
**Current Milestone**: Milestone 0 — Inspection, Planning & Workspace Foundation  
**Last Updated**: 2026-11-09  

---

## 1. Milestone Progress Overview

| Milestone | Description | Status | Progress |
| :--- | :--- | :--- | :--- |
| **Milestone 0** | Workspace inspection, risk assessment, architecture & planning | **COMPLETED** | 100% |
| **Milestone 1** | Minimal desktop shell (pywebview + FastAPI + token auth) | **COMPLETED** | 100% |
| **Milestone 2** | Dataset ingestion, canonical feature schema & baseline ML model | **COMPLETED** | 100% |
| **Milestone 3** | Explainable AI (SHAP integration & deterministic explanations) | **COMPLETED** | 100% |
| **Milestone 4** | Drift monitoring & controlled adaptation sandbox | PENDING | 0% |
| **Milestone 5** | Live packet capture (macOS/Windows) & bidirectional flow processing | PENDING | 0% |
| **Milestone 6** | Desktop dashboard UI, alert management, persistence & reports | PENDING | 0% |
| **Milestone 7** | PyInstaller packaging & cross-platform CI (macOS & Windows) | PENDING | 0% |
| **Milestone 8** | Verification, academic documentation, artifact generation & handover | PENDING | 0% |

---

## 2. Completed Work in Current Milestone (Milestone 3)
- [x] Initialized `shap.TreeExplainer` on the trained Random Forest model (`core/explainability/explainer.py`).
- [x] Implemented fast sub-15ms SHAP attribution extraction across multi-class tree outputs.
- [x] Mapped canonical technical features to plain-language, non-technical descriptions with physical units.
- [x] Created deterministic narrative generator explaining which factors pushed predictions toward attack vs. normal.
- [x] Implemented transparent fallback handling ("Explanation Unavailable") preventing fabricated reasons.
- [x] Integrated XAI engine into FastAPI routes (`/api/explain`, `/api/explain/{event_id}`).
- [x] Added automated unit and integration tests (`tests/unit/test_explainability.py`, `tests/integration/test_api_milestone1.py::test_api_explain_endpoint`) with 25 passing tests.

---

## 2. Completed Work in Current Milestone (Milestone 2)
- [x] Defined Canonical Feature Schema V1 (`core/preprocessing/schema.py`) with 28 bidirectional packet-header and timing features.
- [x] Implemented leak-free `FlowPreprocessor` (`core/preprocessing/preprocessor.py`) with RobustScaler and boundary clipping.
- [x] Authored dataset catalog and benchmark manager (`datasets/manager/dataset_manager.py`) documenting CIC-IDS2017, CSE-CIC-IDS2018, and UNSW-NB15 with reproducible sample generator.
- [x] Built training and evaluation pipeline (`models/training/trainer.py`) executing 70/15/15 stratified train/val/test splits without data leakage.
- [x] Successfully trained Random Forest classifier with balanced weights, saving 445 KB model artifact (`models/trained/baseline_model.joblib`).
- [x] Generated verifiable evaluation report (`models/evaluation/baseline_eval_report.json`) reporting Accuracy, Precision, Recall, F1, FPR, FNR, and confusion matrix.
- [x] Built `ThreatDetector` inference engine (`core/detection/detector.py`) with calibrated confidence, category taxonomy, and standardized severity tiers.
- [x] Integrated detector into lifecycle startup and added `/api/model/info` endpoint.
- [x] Added automated unit tests (`tests/unit/test_schema.py`, `tests/unit/test_preprocessor.py`, `tests/unit/test_detector.py`) with 21 passing tests.

---

## 2. Completed Work in Current Milestone (Milestone 1)
- [x] Python virtual environment configured (`venv`) with dependencies installed (`pywebview`, `fastapi`, `uvicorn`, `scikit-learn`, `shap`, `scapy`, `pytest`, `pandas`, `numpy`).
- [x] Security layer created (`backend/api/auth.py`): loopback client isolation (`127.0.0.1`) and cryptographic per-session token validation (`X-Session-Token`).
- [x] SQLite persistence layer initialized (`backend/database/db.py`) with WAL mode, parameterized queries, and events/drift/model schema.
- [x] Lifecycle manager created (`app/lifecycle.py`) coordinating thread-safe global telemetry and clean shutdown.
- [x] FastAPI REST routes established (`backend/api/routes.py`): health checks, status telemetry, capture interface diagnostics, start/stop controls, and academic metadata.
- [x] Modern desktop frontend built (`frontend/index.html`, `frontend/css/style.css`, `frontend/js/app.js`) with responsive dark theme and live telemetry polling.
- [x] Desktop launcher implemented (`app/launcher.py`): ephemeral loopback port discovery, session token injection, background Uvicorn daemon, health verification, and `pywebview` window.
- [x] Automated test suite added (`tests/unit/test_auth.py`, `tests/unit/test_database.py`, `tests/integration/test_api_milestone1.py`, `tests/integration/test_launcher.py`) with 12 passing tests.

---

## 3. Risks & Platform Strategy

1. **Packet Capture Privileges on macOS**:
   * *Risk*: Live packet capture via Scapy requires read permissions on `/dev/bpf*` devices on macOS. Running the entire desktop application as `sudo` violates security guidelines.
   * *Mitigation*: Implement a BPF permission validator. Provide clear, non-technical instructions for the user (e.g., standard Wireshark/ChmodBPF utility or specific chmod command). Provide an immediate, fully functional **Offline Replay / Demo Mode** so all IDS, XAI, and Drift capabilities are 100% testable without elevated privileges.
2. **Feature Mismatch Between Datasets & Live Flows**:
   * *Risk*: Many academic datasets (like CIC-IDS2017) contain 80+ features, some of which depend on specific flow-meter tools or deep payload parsing that cannot be computed reliably in real-time without latency.
   * *Mitigation*: Establish a rigorous **Canonical Feature Schema (V1)** containing robust statistical flow features computable identically from raw packets and standard flow datasets (duration, packet counts, byte counts, flow rates, inter-arrival times, packet size statistics, TCP flag distributions).
3. **SHAP Computational Overhead**:
   * *Risk*: Generating full SHAP explanations per packet or per high-throughput flow can cause severe latency and stall the UI.
   * *Mitigation*: Use `shap.TreeExplainer` optimized for tree-based ensembles (Random Forest / Extra Trees). Perform XAI computation asynchronously via a worker thread only for flagged suspicious/malicious flows, caching explanations for identical feature profiles.
4. **Windows Packaging without Local Windows Machine**:
   * *Risk*: Developer host is macOS. PyInstaller cannot cross-compile Windows executables from macOS.
   * *Mitigation*: Create a dedicated GitHub Actions workflow using `runs-on: windows-latest` that installs dependencies, executes the test suite, and builds the Windows release artifact cleanly.

---

## 4. Immediate Next Step
- Finalize Milestone 0 documentation and initialize Git repository safely inside `/Users/yudha/Documents/Explainable-Adaptive-IDS/`.
- Present the implementation roadmap and Git repository strategy to the user.
- Upon approval, proceed to **Milestone 1**: Minimal desktop shell with FastAPI backend, per-session token security, pywebview native window, and clean lifecycle management.

---

## 5. Context Handover Instructions
To resume this project in a new session:
1. Working directory: `/Users/yudha/Documents/Explainable-Adaptive-IDS`
2. Inspect `PROJECT_STATUS.md` and `DEVELOPMENT_LOG.md`.
3. Check Git branch status and last verified test.
4. Continue with the current active milestone without restarting from scratch.
