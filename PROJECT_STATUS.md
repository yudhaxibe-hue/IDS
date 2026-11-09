# Project Status & Milestone Tracker

**Project Title**: Explainable Adaptive AI-Based Intrusion Detection System for Changing Network Threats  
**Current Milestone**: Milestone 0 — Inspection, Planning & Workspace Foundation  
**Last Updated**: 2026-11-09  

---

## 1. Milestone Progress Overview

| Milestone | Description | Status | Progress |
| :--- | :--- | :--- | :--- |
| **Milestone 0** | Workspace inspection, risk assessment, architecture & planning | **IN PROGRESS** | 90% |
| **Milestone 1** | Minimal desktop shell (pywebview + FastAPI + token auth) | PENDING | 0% |
| **Milestone 2** | Dataset ingestion, canonical feature schema & baseline ML model | PENDING | 0% |
| **Milestone 3** | Explainable AI (SHAP integration & deterministic explanations) | PENDING | 0% |
| **Milestone 4** | Drift monitoring & controlled adaptation sandbox | PENDING | 0% |
| **Milestone 5** | Live packet capture (macOS/Windows) & bidirectional flow processing | PENDING | 0% |
| **Milestone 6** | Desktop dashboard UI, alert management, persistence & reports | PENDING | 0% |
| **Milestone 7** | PyInstaller packaging & cross-platform CI (macOS & Windows) | PENDING | 0% |
| **Milestone 8** | Verification, academic documentation, artifact generation & handover | PENDING | 0% |

---

## 2. Completed Work in Current Milestone (Milestone 0)
- [x] Host environment inspected: macOS 27.2.0 (ARM64 Apple Silicon), Python 3.9.6, Git 2.54.0, 93 GiB available disk.
- [x] Master engineering specification reviewed in detail.
- [x] Clean directory tree created at `/Users/yudha/Documents/Explainable-Adaptive-IDS/`.
- [x] Module packages (`__init__.py`) and `.gitkeep` markers established.
- [x] `.gitignore` created to prevent committing raw pcaps, datasets, build outputs, databases, or secrets.
- [x] `requirements.txt` crafted with pinned versions compatible with Python 3.9+ on macOS ARM64 and Windows.
- [x] `ARCHITECTURE.md` written defining system components, trust boundaries, data flows, and platform strategy.
- [x] `TEST_PLAN.md` drafted covering unit, integration, ML validation, XAI sanity, and platform capture checks.
- [x] `DEVELOPMENT_LOG.md` initialized for chronological tracking.

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
