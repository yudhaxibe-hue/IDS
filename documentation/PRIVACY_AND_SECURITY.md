# Privacy & Security Assurance

## Explainable Adaptive AI-Based Intrusion Detection System

---

### 1. Architectural Privacy Guarantees

1. **100% Local Inference**:
   * All machine learning inference, SHAP explainability calculations, and statistical drift tests are executed exclusively on the local machine CPU/GPU.
   * Zero external API calls: No communication with OpenAI, Google Gemini, Anthropic, or cloud endpoints.
2. **Zero Telemetry or Data Exfiltration**:
   * The application does not collect usage telemetry, diagnostic pings, crash telemetry, or user analytics.
   * Captured network packets and flow statistics are never transmitted over the internet.
3. **No Packet Payload Storage**:
   * The flow aggregator operates strictly on IP and TCP/UDP transport headers (5-tuples, packet sizes, flags, inter-arrival times).
   * Raw application payloads (HTTP bodies, credentials, packet byte streams) are immediately discarded upon header extraction.
   * No raw `.pcap` files or sensitive payloads are written to the database or exported in reports.

---

### 2. Local Loopback API Threat Model

1. **Loopback-Only Interface Binding**:
   * The FastAPI application server binds exclusively to `127.0.0.1` on an ephemeral port.
   * It never binds to `0.0.0.0` or external LAN/Wi-Fi interfaces.
2. **Per-Session Bearer Token Protection**:
   * At launch, `app/launcher.py` generates a cryptographically random 256-bit hexadecimal session token (`secrets.token_hex(32)`).
   * All protected API routes require the `X-Session-Token` header.
   * Requests lacking the token or presenting an invalid token are rejected with HTTP 403 Forbidden.
3. **Loopback IP Validation Middleware**:
   * In addition to token verification, middleware inspects `request.client.host` to ensure incoming TCP connections originate from `127.0.0.1` or `::1`.
4. **CORS Restrictions**:
   * Cross-Origin Resource Sharing (CORS) is strictly constrained to local webview origins, preventing malicious web pages in external browsers from invoking the local API.

---

### 3. Least Privilege Execution

* **Never Run UI as Administrator/Root**:
  * The entire desktop application should never be executed using `sudo` or as administrator.
  * Live packet capture facilities are isolated behind non-blocking worker threads.
  * On macOS, read access to `/dev/bpf*` can be granted to standard users via the Wireshark `ChmodBPF` startup item.
  * On Windows, Npcap driver handles kernel-level packet inspection safely in user mode.
