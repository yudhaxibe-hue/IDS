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
