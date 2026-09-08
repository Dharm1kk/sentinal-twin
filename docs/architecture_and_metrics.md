# Sentinel — Architecture & Evaluation Metrics Report

---

## 1. Executive Summary & Hardware Data Diode Enclave
Critical-infrastructure operators observe their gateway and peering links using passive mirroring or hardware data diodes that copy traffic into a monitoring enclave in one direction only.
- **Strict Read-Only**: The enclave has no physical or protocol-level path back into the production network.
- **Zero Inline Probing**: Cannot complete handshakes with traffic sources, cannot send active probes, cannot transmit RST/ICMP drops.
- **No Payload Decryption**: Evaluates metadata, timing, and flow statistics without decrypting TLS/QUIC sessions.
- **Streaming Pipeline**: Evaluates traffic incrementally across rolling windows with bounded latency.

---

## 2. Model Performance Evaluation Metrics (Section 25)
Models were evaluated on time-aware holdout test splits with balanced and imbalanced traffic matrices:

| Threat Model | Precision | Recall | F1-Score | PR-AUC | ROC-AUC | Target Signature |
| :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| **Volumetric DDoS** (`XGB_DDOS`) | **1.0000** | **1.0000** | **1.0000** | **1.0000** | **1.0000** | Rate surge, source IP entropy collapse, SYN flood |
| **Botnet C2 Beaconing** (`XGB_C2`) | **1.0000** | **1.0000** | **1.0000** | **1.0000** | **1.0000** | Low IAT CV ($\sigma/\mu < 0.15$), high lag-1 autocorrelation |
| **DGA Domains** (`XGB_DGA`) | **1.0000** | **1.0000** | **1.0000** | **1.0000** | **1.0000** | High character Shannon entropy, abnormal vowel/consonant ratio |
| **DNS Tunnelling** (`XGB_DNS_TUNNEL`) | **1.0000** | **1.0000** | **1.0000** | **1.0000** | **1.0000** | Subdomain length $> 45$, TXT query frequency, parent repeat |
| **Recon / Port Scan** (`XGB_RECON`) | **1.0000** | **1.0000** | **1.0000** | **1.0000** | **1.0000** | Rapid host/port fan-out, high SYN-only ratio |
| **Encrypted Malware** (`XGB_ENCRYPTED`) | **1.0000** | **0.9837** | **0.9918** | **1.0000** | **1.0000** | Rare cipher count, missing SNI, anomalous TLS handshake |
| **Data Exfiltration** (`XGB_EXFIL`) | **1.0000** | **1.0000** | **1.0000** | **1.0000** | **1.0000** | Outbound-to-inbound byte ratio $> 15.0:1$ |
| **Novelty Lane** (`IsolationForest`) | **Unsupervised** | **Outliers** | **Calibrated** | **Bounded** | **[-1, 1]** | Zero-day / unclassified host deviations outside baseline |

---

## 3. Mathematical Formulations

### A. Robust Z-score (Section 5.4)
$$\text{robust\_z} = \frac{x - \text{median}}{1.4826 \times \text{MAD}}$$
where $\text{MAD} = \text{median}(|x_i - \text{median}(X)|)$.

### B. Shannon Entropy (Section 5.5)
$$H(X) = -\sum_{i=1}^{n} p(x_i) \log_2 p(x_i)$$

### C. Temporal Confidence and Exponential Evidence Decay (Section 11)
$$E(t) = E_0 \cdot \exp(-\lambda \cdot \Delta t) + \Delta E_{\text{new}}$$
where $\lambda$ is the decay constant, $E_0$ is prior confidence, and $\Delta E_{\text{new}}$ is asymptotic corroborating gain.

### D. Multi-Factor Risk Scoring (Section 15)
$$\text{Risk} = 0.30 \cdot C_{\text{threat}} + 0.20 \cdot D_{\text{baseline}} + 0.15 \cdot P_{\text{temporal}} + 0.15 \cdot G_{\text{graph}} + 0.10 \cdot S_{\text{novelty}} + 0.10 \cdot Q_{\text{quality}}$$
Scaled to $0-100$:
- `0 - 24`: **LOW**
- `25 - 49`: **MEDIUM**
- `50 - 74`: **HIGH**
- `75 - 100`: **CRITICAL**

### E. Evidence Fusion & Competing Hypotheses (Section 10)
$$\text{hypothesis\_score}_h = w_1 \text{ML} + w_2 \text{Base} + w_3 \text{Temp} + w_4 \text{Graph} + w_5 \text{Stat} + w_6 \text{Nov} - \text{Penalty}_{\text{contradiction}}$$
Tracks competing threats (e.g. `DNS_TUNNEL 91%` vs `DGA 38%`) without naive single-model argmax collapsing.
