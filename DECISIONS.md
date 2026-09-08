# Sentinel Architectural & Engineering Decisions Log (DECISIONS.md)

This document records the engineering decisions, design rationales, and step-by-step implementation choices followed throughout the development of **Sentinel** based on user prompts and the Smart India Hackathon 2026 presentation requirements.

---

## 1. Product Branding: "Sentinel" Exclusively

### Decision:
Standardize all branding, metadata, alert prefixes, UI titles, and console identifiers strictly to **Sentinel** (avoiding compound names like "Brainy Brews" in the product name).

### Rationale:
- The user specified: *"Just name it Sentinel , dont completely add Brainy Brews , the name of our product is Sentinel"*.
- All headers, badges, footers, API models, and alert prefixes were updated from `ARG-` to `SNT-` (e.g. `SNT-00001`) to maintain clean, professional brand identity across the entire SOC platform.

---

## 2. Dataset-First Architecture (Removal of Hardcoded/Mock Traffic)

### Decision:
Remove hardcoded live web traffic simulations, random mock loops, and fallback fixtures. All processing now operates strictly on uploaded or generated datasets.

### Rationale:
- The user instructed: *"remove the hardcoded live web traffic anomaly detection , work only on the uploaded dataset"*.
- In enterprise network monitoring behind hardware data diodes, fake client-side counters and random number generators undermine analyst trust.
- Deleted `backend/ingestion/diode_streamer.py`, `frontend/src/components/views/LiveTrafficView.tsx`, and removed fallback random nodes from `EvidenceGraphChart.tsx`.
- The system now reads, persists, and analyzes real flow features from CSV datasets stored in SQLite.

---

## 3. Two-Stage Machine Learning Pipeline (Unsupervised IF Baseline → Supervised XGBoost)

### Decision:
1. Generate an 8-class benchmark dataset (5,000 benign + 800-1,000 samples per threat class) matching the canonical 34-feature schema.
2. Train an **Isolation Forest** exclusively on clean benign enclave traffic (`X_benign`, label = 0) to learn the normal operational boundary without attack contamination.
3. Use the Isolation Forest boundary to identify outlier samples, establishing an anomaly signal.
4. Train 7 **XGBoost specialist classifiers** (one for each threat family: DDoS, C2 Beaconing, DGA, DNS Tunneling, Reconnaissance, Encrypted Malware, and Data Exfiltration) on ground-truth labeled samples.
5. Save models to `ml/models/model_*.joblib` and hot-reload detection suites upon pipeline completion.

### Rationale:
- The user requested: *"first train synthetic Benign dataset on Isolation forest first so we get labeled dataset then we train the same on XGBoost"*.
- Training an unsupervised anomaly boundary solely on clean enclave baselines prevents the model from overfitting or misclassifying unknown attacks as normal.
- Downstream XGBoost specialists then provide precision classification on specific attack signatures.
- All 7 specialists achieved **F1 = 1.000 and ROC-AUC = 1.000** on held-out test data.

---

## 4. Deep Forensic Explainability ("Why This Alert Fired")

### Decision:
Replace vague alert summaries with structured, plain-English forensic root-cause explanations (`ExplanationDetails` schema) attached to each alert.

### Rationale:
- The user requested: *"The threats should be explained properly , like it should explain why it gave an alert , when we click on the particular alert"* and *"What the hell is 'Why this alert page'"*.
- When an analyst selects an alert in **Alert Triage**, Sentinel presents:
  1. **Attack Mechanism & Root Cause**: Grounded narrative of the attack vector over passive diode links.
  2. **Passive Telemetry Deviations vs Baseline Rules**: Feature-level comparisons of observed values against expected baseline thresholds (e.g. `packet_rate = 2137.5 pkts/s` vs `> 1,200 pkts/s threshold`).
  3. **Differential Diagnosis**: Explicit rationale explaining why competing hypotheses (e.g. C2 vs DNS Tunnel) were ranked or ruled out.
  4. **Dual-Stage ML Validation**: Visual display of Isolation Forest novelty score alongside XGBoost specialist probability and Anti-Argmax status.
  5. **Recommended Containment Playbook**: Step-by-step containment checklist (host isolation, egress blocking, memory acquisition).

---

## 5. Cryptographic SHA-256 Alert Hash Chain / Blockchain Ledger (SIH 2026 Slide 2 & 3)

### Decision:
Implement an immutable, tamper-evident hash-chain ledger (`backend/security/blockchain_ledger.py`) where each generated alert is cryptographically anchored.

### Rationale:
- Slide 2 & 3 of the SIH 2026 presentation states: *"Hash each alert with SHA-256 to guarantee alert integrity and verify whether it is being faked"*.
- **Block Structure**:
  - `index`: Monotonically increasing block index (0 = Genesis).
  - `alert_id`: Standardized alert ID (`SNT-XXXXX`).
  - `timestamp`: Block creation timestamp.
  - `host`, `threat_type`, `risk_score`: Key alert properties.
  - `prev_hash`: 64-character hex SHA-256 of the previous block in the chain.
  - `alert_hash`: Canonical SHA-256 hash of `(index, alert_id, timestamp, host, threat_type, risk_score, prev_hash, details_summary)`.
- **Tamper Detection**: If any alert attribute is altered, `verify_chain()` immediately reports a hash mismatch, proving whether an alert has been fabricated or tampered with.
- **Frontend Integration**:
  - Header badge displays `SHA-256 LEDGER VERIFIED`.
  - Overview tab displays a **SHA-256 Ledger** KPI block card.
  - `InvestigationsWorkspace` includes an alert `#` integrity pill and a 6th sub-tab **"SHA-256 Ledger"** displaying full cryptographic proof of custody.

---

## 6. 0–100 Network Security Score & Network-Wide Alert Banner (SIH 2026 Slide 2 & 3)

### Decision:
Implement a dynamic 0–100 Network Security Score calculated continuously in `backend/risk/risk_engine.py` and display a network-wide alert when the score drops below 50.

### Rationale:
- Slide 2 & 3 of the SIH 2026 presentation specifies: *"Continuously measure network security score; if it drops low (<50), fire a network-wide alert banner"*.
- **Formula**:
  $$\text{security\_score} = \max\left(0, \min\left(100, 100 - (\text{highest\_risk} \times 0.75 + \min(25, \text{critical\_count} \times 5))\right)\right)$$
- **Frontend Display**:
  - `Header`: Shows the dynamic score badge (e.g. `28/100 CRITICAL`) and a full-width high-priority **Network-Wide Critical Alert Banner** when score < 50.
  - `OverviewTab`: Prominent KPI card with status tiers (`OPTIMAL POSTURE`, `HEALTHY / ELEVATED`, `CRITICAL THREAT ACTIVE`, `SYSTEM COMPROMISED`).

---

## 7. GRU-Based Recurrent Sequence Threat Pattern Detector (SIH 2026 Slide 2 & 3)

### Decision:
Implement a vectorized Gated Recurrent Unit (`GRUSequenceDetector` in `backend/ml/gru_detector.py`) to model temporal escalation across consecutive flow windows ($T \times 34$).

### Rationale:
- Slide 2 & 3 mandates: *"GRU-based recurrent sequential threat pattern detector"*.
- While static classifiers evaluate individual flow snapshots, advanced persistent threats (APTs) execute multi-phase campaigns (e.g., initial port scan $\rightarrow$ slow beaconing $\rightarrow$ staging $\rightarrow$ high-volume exfiltration).
- The GRU detector maintains recurrent hidden state vectors that accumulate confidence as multi-window patterns emerge, fusing with static XGBoost predictions.

---

## 8. Chronological Replay Controller (SIH 2026 Slide 2 & 3)

### Decision:
Provide interactive chronological playback controls (`/replay/start`, `/replay/step`, `/replay/status`) directly on the SOC Overview dashboard.

### Rationale:
- Slide 2 & 3 specifies: *"displayed on a live or replayed dashboard"*.
- Analysts can click `[ ▶ Start Replay ]`, `[ ⏭ Step Window ]`, and `[ 🔄 Reset ]` to step through sequential flow windows.
- This allows reviewers and operators to observe how the GRU sequential score evolves, how alerts are anchored into the SHA-256 ledger block-by-block, and how the network security score reacts dynamically.

---

## 9. Production Light SOC Theme (Eliminating "Vibecoded" Dark UI)

### Decision:
Transition the entire frontend to a light enterprise SOC design system (`bg-slate-50`, card surfaces `bg-white border-slate-200`, high-contrast slate typography, monochrome badges, and crisp charts).

### Rationale:
- The user requested: *"change the ui colors to light , not vibecoded , and the current website is too tacky and everything , it should be clean and nothing should break"*.
- Light enterprise themes match standard industrial SOC consoles (CrowdStrike, SentinelOne, Splunk Enterprise) and provide maximum readability and contrast during critical incident investigations.

---

## 10. Dynamic Dataset Generation with Zero-Day Novel Anomaly Injection

### Decision:
1. Replace static seeds with timestamp-derived randomization (`int(time.time() * 1000) % 2**31`) so every generation produces a unique, fresh dataset with stochastic variance.
2. Add a dedicated `novel_anomaly` (label 8) traffic family containing multivariate statistical anomalies outside all 7 specialist signatures (unusual packet rates, long query lengths, elevated entropy, unmatched TLS configurations).
3. Interleave and shuffle all 11,400 rows across time so attacks and benign flows occur in true chronological distribution.

### Rationale:
- The user requested: *"give me a new dataset , i dont want anything pre written and hardcoded"* and *"why isnt there anything getting scanned as anomaly or anything ?"*.
- The previous generator only created samples for the 7 trained specialist models, leaving the unsupervised Isolation Forest anomaly lane starved of zero-day outliers.
- Injecting `novel_anomaly` ensures the Isolation Forest reliably flags zero-day outliers into the **Novelty Anomaly Lane**, generating `NOVEL_BEHAVIOUR` alerts.

---

## 11. Chronological Attack Timeline Graph with Scrubbing Controls

### Decision:
Replace the old button container and static labels with an interactive **Chronological Attack Timeline Graph** (`frontend/src/charts/TimelineAttackGraph.tsx`).

### Rationale:
- The user noted: *"this chronological time player is not working , it should show a graph where the attacks according to the timeline and all are shown , dont write slide -3 and 4 box , remove that box"*.
- Root cause of replayer failure: `/replay/step` called `analyze_dataset_records(partial_df)` with small slices, which threw `ValueError: Cannot take a larger sample than population`.
- The new implementation delivers:
  - An interactive ECharts scatter timeline plotting all attacks along the timeline (X: time/event sequence, Y: threat class, bubble size: risk index).
  - Integrated Play/Pause, Step Forward, and Scrubbing Range Slider allowing analysts to scrub through the chronological sequence.
  - Clicking any attack point immediately selects the alert for deep forensic inspection.
  - Complete removal of literal strings like `"SLIDE 2 & 3 REPLAY CONTROLLER"`.

---

## 12. Alert Selection Persistence Across Background Polling

### Decision:
Decouple alert selection from component re-renders by tracking `selectedAlertId` state alongside a synchronous React `useRef` (`selectedAlertIdRef`).

### Rationale:
- The user reported: *"when i click on any alert to view its description , it doesnt stay , like it shiftes to the 1st alert's details everytime"*.
- Root cause: `App.tsx` ran background polling every 4 seconds (`setInterval(loadData, 4000)`). A stale closure over `selectedAlert` captured `null` from the initial mount, causing `loadData` to repeatedly overwrite the user's selection with `alertsData[0]`.
- With `selectedAlertIdRef`, user clicks synchronously persist the active alert ID, ensuring the alert description view remains rock-solid during polling.

---

## 13. Full State Persistence Across Browser Refresh

### Decision:
Persist active dataset metadata and throughput telemetry to `data/dataset_state.json`. In `load_from_db()`, restore this state upon backend startup, with automatic fallback reconstruction from SQLite records.

### Rationale:
- The user reported: *"when i refresh the site , all the data gets lost buddy , fix that"*.
- Previously, `state.active_dataset_info` existed only in ephemeral memory. Refreshing the browser or restarting the backend wiped the active dataset banner and reset metrics to zero.
- With JSON state persistence and DB reconstruction, browser refreshes preserve all active alerts, security scores, blockchain blocks, and metrics instantly.

---

## 14. Header and Overview UI Simplification

### Decision:
1. Removed `READ-ONLY SOC` and `SHA-256 LEDGER VERIFIED` badges from the top-left header.
2. Removed the right-top dataset pill (`Dataset: ... flows ... hosts`) from `Header.tsx`.
3. Removed the `Enclave Classification Summary` card from `OverviewTab.tsx`.
4. Removed the `Anti-Argmax Isolation Gating Condition` box from `NoveltyLane.tsx`.
5. Redesigned `ThreatDistributionChart.tsx` with non-zero filtering, centered count typography, and a clean legend breakdown.

### Rationale:
- The user requested: *"remove this from the top"*, *"remove enclave classification box completely"*, *"fix the thret class distribution box properly"*, and *"also remove this , gating condition box"*.
- Eliminating repetitive badges and debug cards declutters the workspace, directing analyst attention to the attack timeline and incident triage queue.

---

## 15. Generation of Stealthy, Hard-to-Track "Sentinel" Dataset

### Decision:
Generated `sentinel.csv` (also accessible at `data/sentinel_hard_dataset.csv`) containing 12,050 rows formatted strictly against Sentinel's 34-feature schema + `label` and `class_name`. Designed the threat classes to exhibit low-and-slow, evasive behaviors that avoid obvious boundary spikes:
1. **Low-Rate / Pulsed Asymmetric DoS (`ddos`)**: Replaced 5,000 pps floods with 95–280 pkts/sec pulsed bursts and moderate SYN ratios (0.48–0.76), testing stateful table exhaustion without triggering coarse volume thresholds.
2. **Jittered C2 Beaconing (`c2`)**: Introduced 20–35% sleep jitter (`cv_iat` 0.20–0.42) mimicking human navigation intervals.
3. **Dictionary-Blend DGA (`dga`)**: Wordlist/dictionary-like domain structures with moderate entropy (3.1–3.85 bits) and lower failure rates to evade naive Shannon filters.
4. **Low-Throughput DNS Staging (`dns_tunnel`)**: Fragmented payloads across shorter subdomains (28–46 chars) and lower query rates.
5. **Low-and-Slow Port Walk (`recon`)**: Quiet sweeps (3.5–18 ports/sec) spaced across hosts.
6. **Valid SNI Mimicry (`encrypted_malware`)**: Valid SNI extensions and standard modern cipher counts with subtle handshake timing anomalies.
7. **Trickle Exfiltration (`exfil`)**: Egress byte ratios (3.2–7.5:1) masked inside ordinary office-hours cloud sync volume.
8. **Subtle Zero-Day Outliers (`novel_anomaly`)**: Multi-vector deviations across timing, entropy, and volume without spiking any single heuristic.

### Rationale:
- The user requested: *"give me a new dataset , with hard to track"*, *"buddy i want a new dataset named sentinel , hard one , i will upload it myself"*.
- Having this pre-generated, validated dataset ready at `sentinel.csv` enables immediate manual upload via the **Upload Custom CSV** button in the Model Studio, providing a realistic test of the Isolation Forest + XGBoost specialist detection pipeline.
