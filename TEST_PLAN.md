# System Test Plan & Verification Strategy

## Explainable Adaptive AI-Based Intrusion Detection System

---

### 1. Test Philosophy & Strategy

This test plan defines the testing protocol required to validate the application against the primary engineering specification. Testing spans automated unit testing, integration testing, machine learning metric validation, explainability sanity checks, drift/adaptation validation, and platform-specific manual verification.

No milestone will be marked complete without passing its corresponding automated tests.

---

### 2. Test Suites & Categorization

#### 2.1 Unit Tests (`tests/unit/`)
* **`test_schema.py`**:
  * Verify that canonical feature schema contains expected columns, types, and bounds.
  * Verify deterministic handling of missing values, infinities, and invalid types.
  * Verify that feature order is strictly preserved across transformations.
* **`test_flow_processor.py`**:
  * Verify bidirectional flow aggregation with synthetic packet streams.
  * Verify flow expiration based on inactivity timeout.
  * Verify that packet payloads are not stored in memory or written to disk.
* **`test_detection_model.py`**:
  * Verify model loading from serialized artifact (`joblib`).
  * Verify output probability calibration and score normalization.
  * Verify alert threshold triggering logic (normal vs. suspicious).
* **`test_explainability.py`**:
  * Verify SHAP TreeExplainer generates non-empty feature importance vectors.
  * Verify top feature attribution direction (positive towards malicious vs. negative towards normal).
  * Verify deterministic plain-language template generation for non-technical users.
  * Verify graceful fallback when explanation cannot be generated.
* **`test_drift_detector.py`**:
  * Verify that known stationary data distributions produce zero drift alarms.
  * Verify that statistically shifted distributions (e.g., KS-test p-value < 0.01) trigger drift signals.
  * Verify that candidate models undergo validation before any promotion attempt.
  * Verify model version rollback functionality.
* **`test_security.py`**:
  * Verify loopback-only binding (`127.0.0.1`).
  * Verify API rejection of requests missing or supplying invalid `X-Session-Token`.
  * Verify protection against path traversal in report export endpoints.

#### 2.2 Integration Tests (`tests/integration/`)
* **`test_api_endpoints.py`**:
  * Test `/api/status`, `/api/monitoring/start`, `/api/monitoring/stop`, `/api/alerts`, `/api/explain/{id}`, `/api/drift`, `/api/reports/export`.
* **`test_pipeline_flow_to_alert.py`**:
  * Feed synthetic packet flow -> FlowProcessor -> Preprocessing -> Detection -> Explainability -> SQLite Persistence.
  * Verify complete end-to-end data integrity.
* **`test_replay_mode.py`**:
  * Verify offline replay engine emits valid flow records from a sample CSV/PCAP without raw network socket privileges.

#### 2.3 Packaging & Runtime Tests (`tests/packaging/`)
* **`test_runtime_paths.py`**:
  * Verify bundled asset paths resolution both in raw Python mode and inside PyInstaller frozen bundle (`sys._MEIPASS`).
* **`test_clean_shutdown.py`**:
  * Verify that shutting down the UI cleans up background threads, worker pools, capture handles, and SQLite connections without orphan processes.

---

### 3. Automated Test Execution Commands

```bash
# Run all unit tests
pytest tests/unit/ -v

# Run integration tests
pytest tests/integration/ -v

# Run full test suite with coverage
pytest --cov=core --cov=backend --cov=monitoring tests/ -v
```

---

### 4. Machine Learning & Model Acceptance Criteria

1. **Split Isolation**: Training, validation, and test splits must be split without data leakage. Identifiers such as IP addresses or ports must be handled to prevent memorization if applicable.
2. **Comprehensive Metrics**:
   * Accuracy, Precision, Recall, F1-Score (macro and weighted), False Positive Rate (FPR), False Negative Rate (FNR).
   * Confusion matrix must be recorded and verifiable.
3. **Reproducibility**: Training scripts in `models/training/` must be deterministic with fixed random seeds (`random_state=42`).

---

### 5. Manual Verification Checklist (Before Release)

#### 5.1 Desktop Application & UX
- [ ] Application launches into dedicated desktop window (not browser tab).
- [ ] Repeated launch and close does not leave orphan Python or Uvicorn processes.
- [ ] Status indicator clearly states "Live Monitoring" vs "Demo / Replay Mode".
- [ ] Navigation works smoothly across all tabs (Overview, Live Monitor, Alerts, Explainability, Drift, History, Reports, Settings, About).

#### 5.2 Live Monitoring & Permissions
- [ ] On macOS: App checks read access to `/dev/bpf*` and shows friendly guidance if unpermitted.
- [ ] On Windows: App checks Npcap installation and shows clear download link/instruction if missing.
- [ ] In Replay Mode: Sample flows trigger detection and explanations with zero elevated privileges.

#### 5.3 Explainability
- [ ] Every alert features top contributing features with understandable plain-language descriptions.
- [ ] No fabricated explanations; failures are logged with transparent "Explanation Unavailable" status.

#### 5.4 Controlled Adaptation
- [ ] Drift alert warns the user without unverified automated model replacement.
- [ ] Candidate model requires explicit evaluation and approval before deployment.
- [ ] Rollback button cleanly restores previous approved model version.
