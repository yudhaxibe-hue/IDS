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


---

### [2026-11-09] - Milestone 2: Dataset Acquisition, Canonical Feature Schema & Baseline ML

#### Key Actions Completed:
1. **Canonical Feature Schema V1**:
   - Implemented `core/preprocessing/schema.py` defining 28 statistical flow features (durations, packet counts, byte metrics, inter-arrival times, TCP flag counts, window sizes).
   - Enforced schema boundaries and deterministic imputation (NaN -> defaults, infinities -> min/max bounds).
2. **Leak-Free Preprocessing**:
   - Implemented `core/preprocessing/preprocessor.py` using `RobustScaler(unit_variance=True)` fitted strictly on training data.
3. **Dataset Ingestion & Benchmark Sample**:
   - Created `datasets/manager/dataset_manager.py` with catalog references for CIC-IDS2017, CSE-CIC-IDS2018, and UNSW-NB15.
   - Generated 6,000-record benchmark dataset in `datasets/sample/benchmark_flows.csv` with 60% Normal, 15% DoS/DDoS, 12% Portscan, 8% Brute Force, 5% Web Attack.
4. **Reproducible Model Training & Evaluation**:
   - Built `models/training/trainer.py` with 70% Train, 15% Validation, 15% Test stratified partition.
   - Trained balanced `RandomForestClassifier(n_estimators=100)`.
   - Verified on untouched test set: 100% precision/recall across test partition with zero false positives.
   - Serialized model artifact to `models/trained/baseline_model.joblib` (445 KB) and evaluation report to `models/evaluation/baseline_eval_report.json`.
5. **Inference Engine**:
   - Built `core/detection/detector.py` providing `predict_flow()`, calibrated probability calculation, attack taxonomy resolution, and severity levels.
   - Integrated into application lifecycle and added authenticated `/api/model/info` endpoint.
6. **Automated Testing Suite**:
   - Added unit tests for schema, preprocessor, and detector: 21 passed, 0 failed, 1 skipped.

#### Next Action:
- Commit Milestone 2 to Git.
- Proceed to **Milestone 3**: Explainable AI (SHAP TreeExplainer, feature attribution rankings, and plain-language templates).


---

### [2026-11-09] - Milestone 3: Explainable AI (SHAP TreeExplainer & Deterministic Summaries)

#### Key Actions Completed:
1. **SHAP TreeExplainer Implementation**:
   - Authored `core/explainability/explainer.py` with `IDSExplainer` computing tree SHAP attributions in sub-15ms.
   - Handled multi-class output vectors to extract directed feature contributions.
2. **Plain-Language Non-Technical Mapping**:
   - Mapped all 28 canonical features to clear human labels and units (`Flow Duration` in seconds, `Packet Rate` in pkts/s, `SYN Flag Count`, etc.).
   - Established deterministic attribution ranking (top-k features) and direction flags (positive towards attack, negative towards normal).
3. **Deterministic Plain-Language Summaries**:
   - Created templated narrative generator describing reasons behind alerts without false causal claims.
   - Implemented transparent fallback handling with zero invented explanations.
4. **API Integration & Testing**:
   - Added `/api/explain` and `/api/explain/{event_id}` routes.
   - Added unit and integration tests: 25 passed, 0 failed, 1 skipped.

#### Next Action:
- Commit Milestone 3 to Git.
- Proceed to **Milestone 4**: Drift monitoring & controlled adaptation sandbox.


---

### [2026-11-09] - Milestone 4: Drift Monitoring & Controlled Adaptation Sandbox

#### Key Actions Completed:
1. **Statistical Drift Detection**:
   - Implemented `core/adaptation/drift_detector.py` executing two-sample Kolmogorov-Smirnov (KS) tests on sliding flow feature windows.
   - Guarded against false alarms using minimum window sizes ($N \ge 50$) and multi-feature thresholding.
2. **Model Registry & Candidate Evaluation Sandbox**:
   - Implemented `core/adaptation/model_registry.py` managing versioned model artifacts and SQLite tracking.
   - Enforced strict candidate evaluation gates: candidates must meet $F_1 \ge 0.90$ and $FPR \le 0.05$ against held-out validation protocol prior to promotion.
3. **Reversible Rollback**:
   - Implemented atomic rollback switching the active model pointer to the previous approved version.
4. **API Integration & Testing**:
   - Added `/api/drift`, `/api/adaptation/versions`, and `/api/adaptation/rollback` routes.
   - Added unit and integration tests: 30 passed, 0 failed, 1 skipped.

#### Next Action:
- Commit Milestone 4 to Git.
- Proceed to **Milestone 5**: Live packet capture (macOS BPF / Windows Npcap), bidirectional flow processing, and offline replay demo mode.


---

### [2026-11-09] - Milestone 5: Live Packet Capture, Bidirectional Flow Aggregation & Replay Engine

#### Key Actions Completed:
1. **Common Capture Interface & OS Adapters**:
   - Authored `monitoring/capture/base.py` defining `BaseCaptureAdapter`.
   - Built `monitoring/macos/capture_macos.py` using Scapy `AsyncSniffer(store=False)` and BPF device permission diagnostics.
   - Built `monitoring/windows/capture_windows.py` detecting Npcap driver installation and providing setup instructions.
2. **Bidirectional Flow Processing Engine**:
   - Implemented `monitoring/flow_processing/aggregator.py` grouping packets into 5-tuples.
   - Managed flow duration, forward/backward packet counts, byte volumes, packet length statistics, inter-arrival times, TCP flags, and window sizes.
   - Enforced 15-second inactivity timeout and 120-second active timeout.
   - Ensured zero raw packet payload storage in memory or disk.
3. **Offline Replay / Demo Stream Engine**:
   - Authored `monitoring/flow_processing/replay_engine.py` streaming benchmark flow records at 2.5 flows/sec.
   - Enforced explicit `mode='demo'` tagging on all emitted flows, eliminating unverified claims of live capture during demos.
4. **Unified Pipeline Coordinator**:
   - Authored `monitoring/flow_processing/pipeline.py` bridging capture/replay streams to inference, XAI, SQLite persistence, and drift monitoring.
5. **Testing Suite**:
   - Added `test_flow_aggregator.py`, `test_replay_engine.py`, and `test_capture_prerequisites.py`: 36 passed, 0 failed, 1 skipped.

#### Next Action:
- Commit Milestone 5 to Git.
- Proceed to **Milestone 6**: Desktop dashboard UI polish, alert management, persistence, and report generation.


---

### [2026-11-09] - Milestone 6: Dashboard UI, Alert Management, Persistence & Reports

#### Key Actions Completed:
1. **Frontend-Backend Integration**:
   - Wired all 9 tabs in `frontend/js/app.js` to authenticated backend REST endpoints.
   - Live telemetry polling updates processed flows, malicious count, monitoring mode pill, model version, and drift state.
2. **Alert Management & Explainability UI**:
   - Threat Alerts table features category filtering, severity color badges, and one-click "Inspect XAI" buttons.
   - Explainability tab renders interactive feature attribution tracks and deterministic plain-language summaries.
3. **Drift & Adaptation Controls**:
   - Real-time drift status banner displays "STABLE", "WARNING", or "DRIFT DETECTED" based on KS tests.
   - One-click model rollback button cleanly reverts the active model version to the previous approved artifact.
4. **Reports & Settings Persistence**:
   - Added `/api/reports/csv` for streaming event export.
   - Added `/api/reports/summary` for academic summary generation.
   - Added `/api/settings` for storing configurable alert thresholds and retention periods in SQLite.
5. **Testing Suite**:
   - Added `test_reports_and_settings.py`: 39 passed, 0 failed, 1 skipped.

#### Next Action:
- Commit Milestone 6 to Git.
- Proceed to **Milestone 7**: PyInstaller packaging & cross-platform CI (macOS & Windows).


---

### [2026-11-09] - Milestones 7 & 8: Packaging, CI Automation, Verification & Academic Documentation

#### Key Actions Completed:
1. **PyInstaller Cross-Platform Packaging**:
   - Authored `packaging/macos/ids_macos.spec` and `packaging/windows/ids_windows.spec`.
   - Built native macOS application bundle (`dist/ExplainableAdaptiveIDS.app`) using PyInstaller on macOS ARM64.
   - Packaged release archive `ExplainableAdaptiveIDS-macOS-unsigned.zip` (240 MB) and computed SHA-256 checksum (`7cb0467605bb...`).
2. **GitHub Actions Native CI Workflow**:
   - Authored `.github/workflows/ci.yml` with dual native runner matrix (`macos-latest` and `windows-latest`).
   - Automated testing, model verification, packaging, archive compression, and checksum generation on pull requests and pushes.
3. **Comprehensive Documentation Suite**:
   - `documentation/PROJECT_ABSTRACT.md`: Formal Master of Engineering academic abstract.
   - `documentation/USER_MANUAL.md`: Non-technical installation, first launch, permission guides, and dashboard operations.
   - `documentation/DEVELOPER_GUIDE.md`: Developer environment, test runner, model training, and packaging commands.
   - `documentation/DATASET_AND_MODEL_CARD.md`: Dataset source citations, Canonical Schema V1 table, class distributions, and evaluation metrics.
   - `documentation/PRIVACY_AND_SECURITY.md`: Loopback security, per-session authentication token, zero telemetry, and payload isolation.
   - `documentation/KNOWN_LIMITATIONS.md`: Transparent statement of host observability, detection-only scope, and unsigned prototype status.
4. **Final Verification**:
   - Full automated test suite passed: 39 tests passed, 0 failed, 1 skipped.

#### Git Status:
- Ready for final commit and push to remote origin `https://github.com/yudhaxibe-hue/IDS.git`.
