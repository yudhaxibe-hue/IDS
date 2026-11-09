# Explainable Adaptive Intrusion Detection System (IDS)
## Master of Engineering (M.E.) Defense Script & Technical Guide

**Target Audience**: Master's Professor / Examiner / Viva Committee  
**Purpose**: Crisp, accessible explanation of the architecture, demonstration walkthrough, changes made from the original Word specification, and defensible viva answers.

---

### 1. 30-Second Elevator Pitch (How to Introduce the Project)

> *"Our project is an Explainable and Adaptive AI-Based Intrusion Detection System. Traditional intrusion detection systems operate as black boxes—they flag an attack but cannot explain why, and their accuracy degrades as network traffic patterns change over time.*
>
> *Our system solves both problems by combining three pillars:*
> 1. *Machine Learning Classification (Random Forest on 28 standardized flow features)*
> 2. *Explainable AI (SHAP TreeExplainer providing plain-language reasoning)*
> 3. *Controlled Concept Drift Adaptation (Kolmogorov-Smirnov statistical tests with an audited, rollback-capable candidate model registry).*
>
> *The entire system runs 100% locally with zero cloud telemetry and zero payload storage, protecting enterprise privacy."*

---

### 2. How the System Works (Ball-Level / Easy Explanation)

Think of network traffic like cars on a highway:
* **Traditional Firewalls/Signatures**: Act like security guards checking license plates (IP addresses). If an attacker changes their IP address, they pass through undetected.
* **Our AI Model**: Observes *driving behavior* (packet speed, frequency, payload size, handshake flags). Even if an attacker uses a brand-new IP address, their aggressive driving pattern (DoS flood or portscan) is detected immediately.

#### The 4-Step Pipeline:
1. **Ingestion**: Network packets are captured live (via Scapy BPF/Npcap) or streamed via Offline Replay, aggregated into 5-tuple bidirectional flows (`src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`).
2. **Feature Extraction**: Computes 28 statistical flow metrics (duration, packet rates, inter-arrival times, TCP flags) following the academic CIC-IDS benchmark schema.
3. **ML Classification**: A 100-tree Random Forest classifies the traffic as Normal vs. DoS/DDoS, Portscan, Brute Force, or Web Attacks with calibrated confidence scores.
4. **Explanation & Drift**: SHAP calculates exact mathematical feature weights (explaining *why* the flow was flagged), while a two-sample Kolmogorov-Smirnov test monitors if traffic distributions are drifting over time.

---

### 3. What Was Changed from the Original Word Specification & Why

The project strictly adhered to the primary engineering specification (Milestones 0 to 8). However, **5 practical engineering enhancements** were implemented to ensure stability, ease of evaluation, and academic rigor:

| # | Feature / Area | Original Specification | Refined Enhancement Made | Reason & Academic Justification |
| :--- | :--- | :--- | :--- | :--- |
| **1** | **Display Shell** | Strictly native `pywebview` desktop window. | Added **automatic browser fallback** (Safari / Edge / Chrome) & `--browser` flag. | Prevents crashes if an examiner's computer has an older OS or lacks Cocoa/WebView2 runtime dependencies. |
| **2** | **Launch Usability** | Command-line execution (`python -m app.launcher`). | Created **1-Click Launchers** (`Run_IDS_Mac.command` & `Run_IDS_Windows.bat`). | Non-technical professors ("mam") can launch the app with a simple double-click without touching the terminal or Git. |
| **3** | **Distribution Package** | Local PyInstaller spec files. | Full **GitHub Actions CI/CD pipeline** with automated **Release downloads (v1.0.0)**. | Evaluators can download a single standalone `.zip` file without needing Python or compilers installed. |
| **4** | **Model Adaptation** | Adaptive retraining upon concept drift. | Implemented **audited candidate-model sandbox with 1-click atomic rollback** instead of blind self-training. | **Crucial Defense**: Blind auto-retraining on live network traffic creates an adversarial poisoning risk (attackers can trick the model). Gated human audit prevents this. |
| **5** | **Database Cleanliness** | SQLite database in WAL mode. | Cleaned test leakage and added **automated test teardown fixtures**. | Guarantees evaluators always start with a clean dashboard (0 flows, 0 false alarms) instead of seeing leftover unit-test records. |

---

### 4. 2-Minute Demonstration Walkthrough (What to Click & Say)

* **Step 1: Launch Application**
  * *Action*: Double-click `Run_IDS_Windows.bat` (or `Run_IDS_Mac.command` on Mac).
  * *Say*: *"The application initializes an isolated local FastAPI backend on an ephemeral loopback port (127.0.0.1) with per-session token authentication."*
* **Step 2: Start Monitoring (Offline Replay)**
  * *Action*: Click **Live Monitoring** tab ➔ Select **Demo / Offline Replay Mode** ➔ Click **Start Capture**.
  * *Say*: *"We use Offline Replay Mode to stream realistic benchmark traffic safely. Notice how benign HTTP and TLS traffic increments the Normal counter, while sudden attack bursts are detected and flagged in real time."*
* **Step 3: Inspect Explainable AI (SHAP)**
  * *Action*: Click **Threat Alerts** tab ➔ Click **Explain** on any flagged alert.
  * *Say*: *"Instead of a black box, our system implements TreeSHAP. On the Explainability tab, the waterfall chart shows the exact mathematical contribution of each feature, accompanied by a plain-English explanation detailing why the traffic was flagged."*
* **Step 4: Demonstrate Concept Drift Surveillance**
  * *Action*: Click **Drift & Adaptation** tab.
  * *Say*: *"Two-sample Kolmogorov-Smirnov tests continuously surveil feature distributions against the baseline. If traffic characteristics drift, the system raises a warning and logs candidate models with instant rollback capability."*
* **Step 5: Export Audit Documentation**
  * *Action*: Click **Export Reports** ➔ Click **Export Events to CSV**.
  * *Say*: *"Security analysts can immediately export all alerts and mathematical explanations into a standard CSV spreadsheet for auditing."*

---

### 5. Top 5 Tough Examiner Questions & Winning Answers

#### Q1: "Why did you use Random Forest instead of Deep Learning (LSTM/CNN) or a Large Language Model (LLM)?"
> **Answer**: *"Deep learning models require significant compute resources, exhibit high inference latency (seconds for LLMs), and act as opaque black boxes. In high-speed network security, flows must be classified in sub-milliseconds. Random Forest provides deterministic, high-throughput tabular classification, resists overfitting through bagging, and integrates natively with TreeSHAP for exact polynomial-time explainability."*

#### Q2: "Does the model simply memorize IP addresses and port numbers?"
> **Answer**: *"No. IP addresses and timestamps are strictly excluded from the feature vector. The model is trained solely on 28 behavioral flow statistics (packet timing, byte length distributions, TCP flag counts). An attacker changing their IP address or port will still be detected because their behavioral traffic profile remains anomalous."*

#### Q3: "How does your Explainable AI (XAI) work mathematically?"
> **Answer**: *"We implement TreeSHAP, an algorithm based on cooperative game theory (Shapley values). It computes the exact marginal contribution of each of the 28 features toward the final prediction score relative to the baseline expectation, visualizing both positive (attack-driving) and negative (benign-driving) feature forces."*

#### Q4: "Why not let the model automatically retrain itself on live traffic?"
> **Answer**: *"Blind automated self-training on live network data introduces a severe vulnerability known as Adversarial Concept Drift or Model Poisoning. An attacker could gradually flood the network with malicious traffic to trick the model into accepting attacks as normal. Therefore, our architecture requires candidate evaluation and audited human approval with instant rollback."*

#### Q5: "How do you protect privacy and sensitive data?"
> **Answer**: *"The system is 100% local. It binds exclusively to loopback 127.0.0.1. Raw packet payloads are never stored or transmitted. Only non-reversible statistical flow summaries are computed and stored in a local SQLite database."*
