# Developer & Contributor Guide

## Explainable Adaptive AI-Based Intrusion Detection System

---

### 1. Development Environment Setup

#### Requirements:
* macOS 12+ (Apple Silicon or Intel) or Windows 10/11 (64-bit)
* Python 3.9, 3.10, 3.11, or 3.12
* Git

#### Virtual Environment Configuration:
```bash
# Clone the repository
git clone https://github.com/yudhaxibe-hue/IDS.git
cd IDS

# Create dedicated virtual environment
python3 -m venv venv
source venv/bin/activate       # On Windows: .\venv\Scripts\activate

# Install development dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

---

### 2. Codebase Architecture & Key Modules

| Path | Purpose |
| :--- | :--- |
| `app/launcher.py` | Port selection, session token generation, background server, pywebview shell |
| `app/lifecycle.py` | Application state management, model loading, startup & shutdown hooks |
| `app/main.py` | FastAPI application factory, loopback CORS, static asset mounting |
| `backend/api/auth.py` | Loopback client verification (`127.0.0.1`) and `X-Session-Token` security |
| `backend/api/routes.py` | Authenticated REST endpoints (status, monitoring, alerts, XAI, drift, reports) |
| `backend/database/db.py` | SQLite WAL persistence (`events`, `drift_logs`, `model_registry`, `settings`) |
| `core/preprocessing/schema.py` | Canonical Feature Schema V1 defining 28 flow features and clipping rules |
| `core/preprocessing/preprocessor.py` | Leak-free `RobustScaler` transformation |
| `core/detection/detector.py` | Multi-class scoring, probability calibration, severity assignment |
| `core/explainability/explainer.py` | `shap.TreeExplainer` attribution extraction and deterministic summary generation |
| `core/adaptation/drift_detector.py` | Sliding-window two-sample Kolmogorov-Smirnov (KS) distribution monitoring |
| `core/adaptation/model_registry.py` | Audited version promotion, candidate sandbox evaluation, and rollback |
| `monitoring/flow_processing/` | Bidirectional flow aggregation, replay engine, and ingestion pipeline |

---

### 3. Model Training & Evaluation

To reproduce baseline model training or train on custom flow datasets:
```bash
python -m models.training.trainer
```
This script:
1. Ingests canonical flow data (`datasets/sample/benchmark_flows.csv`).
2. Performs 70% Train, 15% Val, 15% Test stratified partition.
3. Fits the preprocessor strictly on the training partition.
4. Trains a balanced `RandomForestClassifier(n_estimators=100)`.
5. Evaluates comprehensive metrics on the untouched test split and writes `models/evaluation/baseline_eval_report.json`.
6. Saves the serialised bundle to `models/trained/baseline_model.joblib`.

---

### 4. Running Automated Tests

```bash
# Run full test suite with verbose output
pytest tests/ -v

# Run unit tests only
pytest tests/unit/ -v

# Run integration tests only
pytest tests/integration/ -v
```

---

### 5. Packaging & Distribution

#### macOS Build (Local):
```bash
export PYINSTALLER_CONFIG_DIR=/tmp/pyinstaller_cache
pyinstaller packaging/macos/ids_macos.spec --noconfirm
```
Output: `dist/ExplainableAdaptiveIDS.app`

#### Windows Build (GitHub Actions):
The GitHub Actions workflow `.github/workflows/ci.yml` runs on `windows-latest` to build `dist/ExplainableAdaptiveIDS.exe` on native Windows hardware.
