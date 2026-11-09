# System Architecture Specification

## Explainable Adaptive AI-Based Intrusion Detection System for Changing Network Threats

### 1. Architectural Overview & Design Philosophy

The system is designed as an academic M.E.-level, self-contained, privacy-preserving desktop Intrusion Detection System (IDS). It integrates three foundational capabilities into a unified local application:
1. **Machine Learning-Based Intrusion Detection**: High-accuracy binary (Normal vs. Attack) and multi-class category classification on network flow statistics.
2. **Explainable AI (XAI)**: Grounded local explanations using SHAP feature attributions, accompanied by deterministic plain-language translation of network feature influences.
3. **Controlled Adaptation & Drift Monitoring**: Statistical distribution monitoring (e.g., KS-test, Population Stability Index) on streaming flow metrics with an audited, gated model update workflow (no unverified blind self-training).

```
+-------------------------------------------------------------------------------+
|                             Desktop Host (macOS / Windows)                    |
|                                                                               |
|  +-------------------------------------------------------------------------+  |
|  |                pywebview Desktop Native Shell                           |  |
|  |  +-------------------------------------------------------------------+  |  |
|  |  |       Frontend: HTML5 / CSS3 / Vanilla JavaScript                 |  |  |
|  |  |       (Overview, Live Monitor, Alerts, XAI, Drift, Reports)       |  |  |
|  |  +----------------------------------+--------------------------------+  |  |
|  +-------------------------------------|-----------------------------------+  |
|                                        | HTTP/REST (JSON)                     |
|                                        | Loopback Only: 127.0.0.1:<port>      |
|                                        | Per-Session Auth Token               |
|  +-------------------------------------v-----------------------------------+  |
|  |                 FastAPI Application Server (Uvicorn)                    |  |
|  |                                                                         |  |
|  |  +---------------------+  +---------------------+  +-----------------+  |  |
|  |  |  Lifecycle & State  |  |  Persistence Layer  |  | Security & Auth |  |  |
|  |  |  Manager            |  |  (SQLite WAL Mode)  |  | Middleware      |  |  |
|  |  +----------+----------+  +----------+----------+  +--------+--------+  |  |
|  +-------------|------------------------|----------------------|-----------+  |
|                |                        |                      |              |
|  +-------------v------------------------v----------------------v-----------+  |
|  |                           Core Services                                 |  |
|  |                                                                         |  |
|  |  +-------------------------------------------------------------------+  |  |
|  |  | Canonical Feature Schema & Preprocessing Engine                   |  |  |
|  |  +-----------------+-----------------------------------+-------------+  |  |
|  |                    |                                   |                |  |
|  |  +-----------------v-----------------+   +-------------v-------------+  |  |
|  |  | Detection & Classification Engine |   | Drift Monitoring Engine   |  |  |
|  |  | (Random Forest / Extra Trees)     |   | (Statistical Distribution)|  |  |
|  |  +-----------------+-----------------+   +-------------+-------------+  |  |
|  |                    |                                   |                |  |
|  |  +-----------------v-----------------+   +-------------v-------------+  |  |
|  |  | Explainability Engine (SHAP)      |   | Model Adaptation Registry |  |  |
|  |  | (Feature Contribution & Summary)  |   | (Candidate Eval & Rollback|  |  |
|  |  +-----------------------------------+   +---------------------------+  |  |
|  +-----------------------------^-------------------------------------------+  |
|                                | Completed Bi-directional Flows               |
|  +-----------------------------+-------------------------------------------+  |
|  |                   Monitoring & Ingestion Subsystem                      |  |
|  |                                                                         |  |
|  |  +--------------------------+           +----------------------------+  |  |
|  |  |  Flow Aggregation Engine |           |  Offline Replay / Demo     |  |  |
|  |  |  (Bi-directional / Keyed)|           |  Simulator Engine          |  |  |
|  |  +------------^-------------+           +--------------^-------------+  |  |
|  |               |                                        |                |  |
|  |  +------------+-------------+                         |                |  |
|  |  | OS Packet Capture Driver |                         |                |  |
|  |  | [macOS: BPF / Scapy]     |                         |                |  |
|  |  | [Windows: Npcap / Scapy] |                         |                |  |
|  +--+--------------------------+-------------------------+-----------------+  |
+-------------------------------------------------------------------------------+
```

---

### 2. Component Boundaries and Module Responsibilities

#### 2.1 Application Shell (`app/`)
* **`launcher.py`**: Initializes the desktop application. Detects an available local port on `127.0.0.1`, generates a cryptographically secure per-session authentication token (UUID4), spawns the FastAPI/Uvicorn backend in a managed daemon thread, verifies API health, and initializes the native `pywebview` window pointing to the local dashboard.
* **`lifecycle.py`**: Orchestrates application startup and graceful shutdown. Ensures packet capture threads, background inference queues, database connections, and worker pools are safely stopped and flushed before process exit.
* **`main.py`**: Developer and packaging entry point.

#### 2.2 Backend & API (`backend/`)
* **`backend/api/`**: FastAPI routing layer. Exposes REST endpoints for monitoring control, alert feeds, explainability queries, drift status, model versioning, settings, and report downloads.
* **`backend/services/`**: Bridges HTTP requests to core domain engines (InferenceService, MonitoringService, ExplainabilityService, AdaptationService).
* **`backend/database/`**: SQLite persistence management. Uses WAL (Write-Ahead Logging) mode, parameterized queries, automated schema migrations, and bounded retention trimming.

#### 2.3 Core Domain Engines (`core/`)
* **`core/preprocessing/`**: The canonical feature schema definition and validation engine. Ensures that incoming network flows, offline dataset records, training splits, and live inference vectors share identical column names, ordering, data types, and scaling transformations.
* **`core/detection/`**: Binary classifier scoring. Emits calibrated probabilities or normalized model scores alongside configurable alert thresholds.
* **`core/classification/`**: Multi-class attack taxonomy classification (e.g., DoS/DDoS, Portscan, Brute Force, Web Attack) trained strictly on verified dataset labels.
* **`core/explainability/`**: SHAP-powered local explainability. Computes top feature attributions per flagged event and translates raw feature statistics into human-understandable deterministic explanations.
* **`core/adaptation/`**: Drift detector computing statistical distances between baseline training distributions and streaming production flow features. Manages the candidate model evaluation sandbox and rollback registry.

#### 2.4 Monitoring & Capture Subsystem (`monitoring/`)
* **`monitoring/capture/`**: Common abstract capture interface defining `start_capture()`, `stop_capture()`, `get_interfaces()`, and health checks.
* **`monitoring/macos/`**: macOS BPF-based capture adapter utilizing Scapy. Handles BPF permission checks and user guidance.
* **`monitoring/windows/`**: Windows capture adapter detecting Npcap installation and adapter status.
* **`monitoring/flow_processing/`**: Assembles raw packets into bidirectional 5-tuple network flows `(Src IP, Dst IP, Src Port, Dst Port, Protocol)` with configurable flow timeouts. Computes standard statistical flow metrics without inspecting or storing packet payloads.
* **`monitoring/replay/`**: Offline replay simulator providing reproducible test and demo streams without needing raw network capture privileges.

#### 2.5 Presentation Layer (`frontend/`)
* Built with pure standards: HTML5, CSS3, and Vanilla JavaScript (ES6+). Zero heavy frontend frameworks (no React, Angular, or Node.js runtime).
* Renders real-time telemetry, monitoring status, alert lists, interactive SHAP waterfall/bar visualizations, drift metrics, and history filters.

---

### 3. Trust Boundaries & Security Architecture

1. **Loopback Isolation**: The FastAPI backend binds strictly to `127.0.0.1`. It never binds to `0.0.0.0` or network-facing interfaces.
2. **Session Authentication**: All API requests from the frontend must include the per-session token in the `X-Session-Token` header. Requests failing authentication are rejected with HTTP 403.
3. **CORS Restrictions**: CORS origins are restricted to the local loopback origin hosting the webview.
4. **No Remote Execution / No Payload Leakage**: Raw packet payloads are never stored in SQLite or transmitted across API endpoints. The system extracts statistical flow metrics only.
5. **Privacy Guarantee**: Zero external telemetry, zero third-party cloud API dependencies, and zero outbound network transmission of user traffic or alerts.
6. **Least Privilege Capture**: The application never runs the entire UI or backend as root/administrator. Only capture threads touch OS packet capture facilities.

---

### 4. Canonical Feature Schema Strategy

A foundational failure mode in ML-based IDS is **feature mismatch** between training datasets and live packet capture. To guarantee integrity:
* All models and feature extractors adhere to `CANONICAL_SCHEMA_V1`.
* Only features that can be computed deterministically from bi-directional flow headers and timing (e.g., packet counts, byte counts, flow duration, inter-arrival times, packet length statistics, flag counts) are included.
* Features requiring proprietary deep-packet-inspection payload decoders or unattainable dataset-specific fields are excluded.
* Feature vectors are validated against schema bounds prior to model inference.

---

### 5. Platform Differences & Strategy

| Feature | macOS (Development & Local Build) | Windows (CI GitHub Actions Build) |
| :--- | :--- | :--- |
| **Capture Backend** | Scapy with BPF devices (`/dev/bpf*`) | Scapy with Npcap driver |
| **Prerequisites** | Read permissions on `/dev/bpf*` | Npcap installed in WinPcap compatibility mode |
| **Desktop WebView** | WebKit (`pywebview` default on macOS) | WebView2 (`Microsoft.Web.WebView2`) |
| **Packaging Target** | `.app` bundle / `.dmg` disk image via PyInstaller | `.exe` standalone / installer via PyInstaller |
| **Build Host** | Local Apple Silicon / macOS host | Windows GitHub Actions Runner (`windows-latest`) |
