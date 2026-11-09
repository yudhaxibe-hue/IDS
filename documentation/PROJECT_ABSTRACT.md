# Academic Project Abstract

## Explainable Adaptive AI-Based Intrusion Detection System for Changing Network Threats

### Degree & Academic Level
**Master of Engineering (M.E.) Capstone Prototype**

---

### Abstract
The increasing complexity and continuously changing nature of cyberattacks create an urgent requirement for intrusion detection systems (IDS) that can identify malicious network activity and adapt to evolving attack patterns. Conventional signature-based security tools struggle to detect zero-day variants, while black-box deep learning models fail to offer transparency or explainability to human security analysts.

This research project develops an **Explainable Adaptive AI-Based Intrusion Detection System** capable of detecting, classifying, and explaining suspicious network traffic within a local desktop application. The system processes bidirectional network flows and converts packet observations into a standardized 28-feature canonical representation computable in real-time from packet headers and flow timing statistics. A machine learning model—trained on freely accessible cybersecurity datasets—classifies traffic into benign activity versus high-priority attack families (DoS/DDoS, Portscan, Brute Force, Web Attacks).

To address concept drift and evolving network conditions, an adaptive component continuously monitors streaming flow feature distributions using two-sample Kolmogorov-Smirnov (KS) statistical tests. When statistically significant distribution shifts occur, the system triggers audited drift alerts and enables a controlled, sandboxed candidate-model evaluation and reversible rollback workflow, avoiding the risks of uncontrolled or blind self-training on unlabeled traffic.

To ensure interpretability, an Explainable AI (XAI) subsystem grounded in SHAP (SHapley Additive exPlanations) TreeExplainer analyzes each alert. The system extracts local feature attributions and generates deterministic plain-language explanations that articulate the primary feature contributions driving the detection decision without making unverified causal claims.

The prototype is packaged as a cross-platform desktop application using `pywebview` and a local FastAPI backend bound strictly to the loopback interface (`127.0.0.1`) with per-session token authorization. All inference, explainability computations, and event persistence operate entirely locally on host resources without external AI APIs, cloud infrastructure, or third-party data transmission. The result is a practical, cost-effective, privacy-preserving, and transparent intrusion detection prototype for modern network defense.

---

### Core Contribution Matrix
1. **Machine Learning Detection**: Standardized bidirectional flow feature aggregation classified by balanced Random Forest / Extra Trees ensembles.
2. **Explainable AI (XAI)**: Low-latency local SHAP feature attributions translated into human-readable deterministic narratives.
3. **Controlled Adaptation**: Sliding-window Kolmogorov-Smirnov concept drift surveillance coupled with sandboxed candidate model acceptance gates and reversible rollback.
4. **Privacy-Preserving Local Desktop Architecture**: Loopback-only REST API with per-session token protection and zero raw packet payload retention.
