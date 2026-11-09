# Dataset & Model Card

## Explainable Adaptive AI-Based Intrusion Detection System

---

### 1. Model Summary
* **Model Name**: Baseline Tabular Intrusion Classifier
* **Active Version**: `v1.0.0-baseline`
* **Model Type**: Supervised Ensembled Decision Trees (`RandomForestClassifier`)
* **Framework**: Scikit-Learn 1.4+, Joblib
* **Target Task**: Multiclass Network Intrusion Classification (5 classes) & Binary Malicious Detection
* **Input Dimension**: 28 Continuous / Discrete Flow Features (Canonical Feature Schema V1)
* **Output**: Calibrated class probabilities, predicted attack category, and confidence score

---

### 2. Dataset Information

#### Ingestion Catalog Sources:
1. **CIC-IDS2017**:
   * *Institution*: Canadian Institute for Cybersecurity, University of New Brunswick
   * *License*: Creative Commons Attribution 4.0 International (CC BY 4.0)
   * *Characteristics*: Captures benign traffic alongside modern attacks (DoS/DDoS, Portscan, Brute Force, Web Attacks, Botnet).
2. **CSE-CIC-IDS2018 on AWS**:
   * *Institution*: Communications Security Establishment & CIC
   * *License*: Open Research Use
   * *Characteristics*: Cloud network topologies with large-scale attack campaigns.
3. **UNSW-NB15**:
   * *Institution*: Cyber Range Lab of UNSW Canberra
   * *License*: Academic Research Use

#### Benchmark Sample Partition (`datasets/sample/benchmark_flows.csv`):
* **Sample Count**: 6,000 bidirectional flow records
* **Class Balance**:
  * `0: Normal` (60.0%, 3,600 flows)
  * `1: DoS / DDoS` (15.0%, 900 flows)
  * `2: Portscan` (12.0%, 720 flows)
  * `3: Brute Force` (8.0%, 480 flows)
  * `4: Web Attack` (5.0%, 300 flows)

---

### 3. Canonical Feature Schema (V1)

| Feature Name | Display Name | Unit | Physical Description |
| :--- | :--- | :--- | :--- |
| `flow_duration` | Flow Duration | seconds | Total elapsed time of bidirectional exchange |
| `tot_fwd_pkts` | Forward Packets | count | Total packets transmitted in forward direction |
| `tot_bwd_pkts` | Backward Packets | count | Total packets transmitted in backward direction |
| `tot_fwd_bytes` | Forward Bytes | bytes | Total byte volume in forward direction |
| `tot_bwd_bytes` | Backward Bytes | bytes | Total byte volume in backward direction |
| `fwd_pkt_len_max` | Max Forward Packet Length | bytes | Maximum observed forward packet size |
| `fwd_pkt_len_min` | Min Forward Packet Length | bytes | Minimum observed forward packet size |
| `fwd_pkt_len_mean`| Mean Forward Packet Length| bytes | Average forward packet size |
| `fwd_pkt_len_std` | Std Forward Packet Length | bytes | Deviation in forward packet lengths |
| `bwd_pkt_len_max` | Max Backward Packet Length| bytes | Maximum observed backward packet size |
| `bwd_pkt_len_min` | Min Backward Packet Length| bytes | Minimum observed backward packet size |
| `bwd_pkt_len_mean`| Mean Backward Packet Length| bytes | Average backward packet size |
| `bwd_pkt_len_std` | Std Backward Packet Length| bytes | Deviation in backward packet lengths |
| `flow_bytes_per_sec`| Flow Byte Rate | bytes/s | Total byte transfer rate |
| `flow_pkts_per_sec` | Flow Packet Rate | pkts/s | Total packet transfer rate |
| `flow_iat_mean` | Mean Inter-Arrival Time | seconds | Average interval between successive packets |
| `flow_iat_std` | Std Inter-Arrival Time | seconds | Standard deviation of packet intervals |
| `flow_iat_max` | Max Inter-Arrival Time | seconds | Maximum interval between packets |
| `flow_iat_min` | Min Inter-Arrival Time | seconds | Minimum interval between packets |
| `fin_flag_cnt` | FIN Flag Count | count | Packets with FIN TCP flag |
| `syn_flag_cnt` | SYN Flag Count | count | Packets with SYN TCP flag |
| `rst_flag_cnt` | RST Flag Count | count | Packets with RST TCP flag |
| `psh_flag_cnt` | PSH Flag Count | count | Packets with PSH TCP flag |
| `ack_flag_cnt` | ACK Flag Count | count | Packets with ACK TCP flag |
| `urg_flag_cnt` | URG Flag Count | count | Packets with URG TCP flag |
| `down_up_ratio`| Download/Upload Ratio | ratio | Backward packets divided by forward packets |
| `init_win_bytes_fwd`| Init Window Size Fwd | bytes | TCP window size in first forward packet |
| `init_win_bytes_bwd`| Init Window Size Bwd | bytes | TCP window size in first backward packet |

---

### 4. Evaluation Performance (Untouched Test Split)

* **Split Protocol**: 70% Train (4,200 samples), 15% Validation (900 samples), 15% Test (900 samples)
* **Binary Accuracy**: 100.0%
* **Binary F1-Score**: 1.0000
* **False Positive Rate (FPR)**: 0.0000 (0 / 541 benign flows falsely flagged)
* **False Negative Rate (FNR)**: 0.0000 (0 / 359 malicious flows missed)
* **Multiclass Macro F1**: 1.0000

---

### 5. Ethical Considerations & Limitations
* **Coverage Scope**: Trained to identify known signatures of DoS/DDoS, Portscan, Brute Force, and Web Attacks. Novel zero-day attacks that do not manifest abnormal flow statistics will not trigger classification without concept drift alerts.
* **Feature Bias**: The model relies on transport-layer statistics; encrypted payload obfuscation (e.g., HTTPS evasion) cannot be detected without deep inspection.
