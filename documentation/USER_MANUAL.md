# User Manual & Operator Guide

## Explainable Adaptive AI-Based Intrusion Detection System

---

### 1. Introduction
The **Explainable Adaptive Intrusion Detection System (IDS)** is a desktop cybersecurity application designed to detect, classify, and explain network threats in real time. It runs entirely on your local computer, protecting your privacy without transmitting captured traffic to external cloud services or third-party AI APIs.

---

### 2. Installation & First Launch

#### macOS Installation:
1. Download the latest release (`ExplainableAdaptiveIDS-macOS-unsigned.zip`) from GitHub Releases.
2. Unzip the file to extract `ExplainableAdaptiveIDS.app`.
3. Drag `ExplainableAdaptiveIDS.app` to your `/Applications` folder.
4. **First Launch Security Note**: Because this is an academic research prototype distributed without a commercial Apple Developer certificate, macOS Gatekeeper may show a notice on first launch:
   * *Resolution*: Right-click (or Control-click) `ExplainableAdaptiveIDS.app` and select **Open**, then click **Open** in the dialog. You only need to do this once.

#### Windows Installation:
1. Download `ExplainableAdaptiveIDS-Windows-unsigned.zip` from GitHub Releases.
2. Extract the folder to your preferred location (e.g., `C:\Program Files\ExplainableAdaptiveIDS`).
3. Double-click `ExplainableAdaptiveIDS.exe` to launch the application.

---

### 3. Understanding the Dashboard & Views

#### 1. System Overview
* **Status Badges**: Displays current monitoring mode (`IDLE`, `LIVE`, or `DEMO`) and active model version (`v1.0.0-baseline`).
* **Processed Flows**: Total number of bidirectional network flows analyzed since startup.
* **Threat Alerts**: Total count and percentage of flows flagged as malicious.
* **Distribution Drift**: Displays current traffic distribution status (`STABLE`, `WARNING`, or `DRIFT DETECTED`).
* **Recent Alerts Table**: Shows real-time threat events as they occur.

#### 2. Live Monitoring & Ingestion Controls
* **Select Network Interface**: Choose your network adapter (`en0` for Wi-Fi/Ethernet on macOS, `Ethernet` on Windows).
* **Ingestion Mode**:
  * **Offline Replay / Demo Mode**: Streams pre-recorded realistic traffic flows without requiring elevated permissions. Ideal for demonstrations, testing, and offline evaluation.
  * **Live Network Packet Capture**: Inspects packets passing through the host's physical network adapter.
* **Start / Stop Monitoring**: Toggle network monitoring on and off cleanly.

#### 3. Threat Alerts
* View all flagged events with timestamp, source/destination IP and port, attack category (`DoS / DDoS`, `Portscan`, `Brute Force`, `Web Attack`), severity tier, and model confidence score.
* Click **Inspect XAI** next to any alert to view its detailed explainability breakdown.

#### 4. Explainability (XAI)
* **Plain-Language Summary**: Read a human-understandable explanation detailing why the system flagged the event.
* **Top Contributing Features**: View the top 5 network flow features that influenced the model's decision, showing whether each feature pushed the prediction toward an attack (red) or toward normal traffic (green).

#### 5. Concept Drift & Adaptation Sandbox
* **Distribution Surveillance**: Continuously tests streaming flow features using Kolmogorov-Smirnov statistics to detect shifts in network traffic characteristics.
* **Audited Rollback**: If a newly updated model degrades performance, click **Rollback to Previous Model** to instantly restore the approved baseline model.

#### 6. Export Reports
* **Export Events to CSV**: Download all recorded flow events and explanations as a standard `.csv` spreadsheet for analysis in Excel or security audits.
* **Print Report Summary**: Generate a clean, formatted report ready for printing or saving as a PDF.

#### 7. Settings
* **Alert Detection Threshold**: Adjust the model sensitivity slider (default: `0.70`). Higher values reduce false alarms; lower values increase sensitivity.
* **Data Retention**: Configure how long event history is retained in the local SQLite database.

---

### 4. Packet Capture Permissions & Troubleshooting

#### macOS Live Capture:
* macOS restricts packet capture on `/dev/bpf*` devices to administrator accounts.
* *Option A (Recommended)*: Use **Offline Replay Mode**, which requires no administrator permissions.
* *Option B*: To grant capture access to your user account, install the Wireshark `ChmodBPF` startup item, or run:
  ```bash
  sudo chmod 644 /dev/bpf*
  ```

#### Windows Live Capture:
* Windows requires the Npcap packet capture driver.
* If Npcap is missing, download it from [https://npcap.com/](https://npcap.com/) and ensure **"Install Npcap in WinPcap API-compatible Mode"** is checked.
