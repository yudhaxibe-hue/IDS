# Known Limitations & Academic Boundary Specification

## Explainable Adaptive AI-Based Intrusion Detection System

---

### 1. Honest Scope & Explicit Non-Capabilities

1. **Host-Observable Traffic Only**:
   * The application monitors traffic that reaches the local host's physical network adapters (e.g., incoming packets addressed to the host, broadcast/multicast packets, and outgoing connections).
   * **Limitation**: The prototype does not and cannot monitor other independent devices on the same Wi-Fi router (such as smartphones or smart TVs) unless configured with a network TAP, switch port mirroring (SPAN), or router gateway tap.
2. **Detection-Only (IDS, not IPS)**:
   * The system is an Intrusion Detection System (IDS). It analyzes, classifies, explains, and logs suspicious activity.
   * **Limitation**: It does not act as an Intrusion Prevention System (IPS). It does not automatically modify firewall rules, inject TCP RST packets, block IP addresses, or disrupt running network sockets.
3. **No Claim of Perfect Security**:
   * Machine learning classifiers output probabilistic confidence scores, not absolute certainty.
   * An alert indicates statistical similarity to known attack patterns, not guaranteed evidence of breach.
4. **Encrypted Payload Blindness**:
   * The system relies exclusively on statistical transport-layer flow metadata (packet lengths, timing, flags).
   * It cannot inspect encrypted SSL/TLS application contents without active HTTPS interception/termination.
5. **Drift Is Not Proof of Attack**:
   * Concept drift indicates that incoming traffic distributions have shifted from the baseline training distribution.
   * Drift may result from benign causes (e.g., video streaming, software updates, peak-hour workload changes).
   * Unlabeled traffic is never automatically trained on as ground truth.
6. **Code-Signing Status**:
   * Executables are built from open source as academic prototypes and are distributed unsigned.
   * macOS Gatekeeper and Windows Defender SmartScreen may display warnings on first execution that require manual user confirmation to proceed.
