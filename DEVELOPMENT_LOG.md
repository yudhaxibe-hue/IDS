# Development Log

This document maintains a chronological, dated record of all engineering changes, milestone completions, test executions, and technical decisions.

---

### [2026-11-09] - Milestone 0: Initialization, Inspection & Architecture Foundation

#### Environmental Inspection:
- **Operating System**: macOS Darwin 27.2.0 (macOS 15/16 on Apple Silicon M-series, ARM64).
- **Python Runtime**: Python 3.9.6 located at `/usr/bin/python3` with standard `venv` support.
- **Source Control**: Git version 2.54.0 (Apple Git-157).
- **Available Storage**: 93 GiB available on `/System/Volumes/Data`.
- **Target Project Root**: `/Users/yudha/Documents/Explainable-Adaptive-IDS`.

#### Key Actions Completed:
1. **Repository Layout Established**:
   - Created full modular folder hierarchy: `app/`, `backend/`, `core/`, `monitoring/`, `models/`, `datasets/`, `packaging/`, `tests/`, `documentation/`, and `.github/workflows/`.
   - Initialized Python module structure with empty `__init__.py` files and `.gitkeep` placeholders.
2. **Security & Privacy Guardrails**:
   - Configured comprehensive `.gitignore` ensuring that raw network pcaps, runtime databases, large datasets, logs, compiled bytecode, virtual environments, and signing keys are never tracked by Git.
3. **Dependency Plan Formulated**:
   - Created `requirements.txt` specifying exact, compatible version ranges for `pywebview`, `fastapi`, `uvicorn`, `pydantic`, `scikit-learn`, `shap`, `scapy`, and `pytest`.
4. **Core Technical Documentation Authored**:
   - `ARCHITECTURE.md`: Authored system architecture, module boundaries, data flow, trust model, and platform adapters.
   - `PROJECT_STATUS.md`: Established milestone tracker, risk mitigation matrix, and session handover procedure.
   - `TEST_PLAN.md`: Drafted verification strategy covering unit, integration, machine learning, XAI correctness, and platform capture.

#### Risks Identified & Mitigated:
- **macOS BPF Capture Permissions**: Addressed via BPF validator and dual-mode architecture (Live Monitoring + Offline Replay Demo).
- **Live vs. Training Feature Schema Inconsistency**: Addressed via strict `CanonicalFeatureSchema` enforcing deterministic flow metric calculations.
- **SHAP Runtime Overhead**: Addressed via asynchronous explanation of alerts using `shap.TreeExplainer`.
- **Cross-Platform Build Constraints**: Addressed by isolating macOS packaging to macOS and Windows packaging to GitHub Actions `windows-latest` runners.

#### Next Action:
- Commit Milestone 0 baseline to Git.
- Confirm roadmap with user and begin Milestone 1 (Desktop shell, FastAPI backend, lifecycle, and loopback token security).


---

### [2026-11-09] - Milestone 1: Minimal Desktop Shell, Loopback Backend & Security Layer

#### Key Actions Completed:
1. **Virtual Environment & Dependencies**:
   - Initialized Python 3.9 venv in `venv/`.
   - Installed core dependencies: `pywebview 4.4.1`, `fastapi 0.128.8`, `uvicorn 0.39.0`, `scikit-learn 1.4.2`, `shap 0.49.1`, `scapy 2.8.0`, `pandas 2.3.3`, `numpy 1.26.4`, `pytest 8.4.2`.
2. **Loopback-Only Security & Session Token Validation**:
   - Authored `backend/api/auth.py` providing `verify_loopback_only` and `verify_local_request`.
   - Strict loopback IP filtering (`127.0.0.1`, `::1`) and per-session bearer tokens via `X-Session-Token` header.
3. **Database Architecture**:
   - Authored `backend/database/db.py` setting up SQLite in WAL mode.
   - Initialized schemas for `events`, `drift_logs`, `model_registry`, and `settings`.
4. **FastAPI Application & REST Routing**:
   - Authored `app/main.py` with lifespan hooks and loopback CORS.
   - Authored `backend/api/routes.py` with `/api/health`, `/api/status`, `/api/interfaces`, `/api/monitoring/start|stop`, `/api/events`, and `/api/about`.
5. **Desktop Frontend GUI**:
   - Developed `frontend/index.html`, `frontend/css/style.css`, and `frontend/js/app.js`.
   - Responsive dark cybersecurity theme with navigation tabs, live telemetry polling, and start/stop monitoring controls.
6. **Launcher & Desktop Window Lifecycle**:
   - Authored `app/launcher.py` with ephemeral loopback port discovery, Uvicorn server background thread, health probing, and `pywebview.create_window`.
7. **Automated Testing Suite**:
   - Created `tests/unit/test_auth.py`, `tests/unit/test_database.py`, `tests/integration/test_api_milestone1.py`, and `tests/integration/test_launcher.py`.
   - Executed test suite: 12 passed, 0 failed, 1 skipped.

#### Next Action:
- Commit Milestone 1 changes to Git.
- Proceed to **Milestone 2**: Dataset ingestion, canonical feature schema V1, and baseline ML model training & evaluation.
