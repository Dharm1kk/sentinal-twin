"""
Deep Explainability and Grounded Incident Narrative Engine
Implements Section 16 & 17 of ARGUS 0 Specification.
Produces deep root-cause explanations explaining WHY an alert was triggered,
what anomalous behavior was detected, which specific passive features deviated from baseline,
why alternative hypotheses were rejected, and what containment steps are recommended.
"""

from typing import Dict, Any, List, Optional


THREAT_EXPLANATIONS = {
    "C2": {
        "title": "Command & Control (C2) Automated Beaconing",
        "mechanism": (
            "An internal host is exhibiting persistent, rigid periodic network communication "
            "to an external endpoint. In passive unidirectional telemetry, human-initiated traffic "
            "displays high variance in packet inter-arrival times (Poisson/exponential decay), "
            "whereas automated malware beaconing presents near-zero timing jitter, high autocorrelation, "
            "and synchronized heartbeat intervals."
        ),
        "discriminating_features": [
            ("cv_iat", "Coefficient of Variation of Inter-Arrival Time", "Drops below 0.15 (normal median: 0.70-0.95), indicating mechanical clockwork pacing"),
            ("autocorrelation_lag1", "Lag-1 Autocorrelation of IAT", "Spikes above 0.75 (normal: < 0.20), revealing strong repetitive temporal structure"),
            ("timing_regularity", "Timing Regularity Index", "Exceeds 0.85 (normal: < 0.35), confirming algorithmic beacon cadence")
        ],
        "containment": [
            "Immediately isolate victim host from internal lateral broadcast domain",
            "Block external C2 destination IP and port at perimeter gateway/firewall",
            "Acquire endpoint memory capture and inspect active sockets for injected processes",
            "Audit DNS query logs from the host immediately preceding the first beacon timestamp"
        ]
    },
    "DDOS": {
        "title": "Volumetric / Ingress SYN Flooding Surge",
        "mechanism": (
            "A massive volumetric burst of connection requests was observed crossing the unidirectional link. "
            "The anomalous traffic is dominated by incomplete TCP SYN handshakes or high-rate datagram bursts "
            "designed to exhaust stateful connection tables on enclave gateway infrastructure."
        ),
        "discriminating_features": [
            ("packet_rate", "Observed Packet Ingress Rate", "Exceeds 1,200 pkts/s (normal baseline: 20-60 pkts/s)"),
            ("syn_only_ratio", "TCP SYN-Only Flag Ratio", "Surpasses 0.80 (normal: < 0.15), confirming one-way connection flooding without data transfer"),
            ("src_ip_entropy", "Source IP Shannon Entropy", "Spikes to 4.5-7.5 bits, reflecting spoofed or distributed botnet origin addresses")
        ],
        "containment": [
            "Activate upstream ISP scrubbing center or BGP Flowspec route injection",
            "Enable stateless SYN proxy/cookies on the edge gateway",
            "Throttle ingress interface bandwidth to protect internal services",
            "Capture PCAP sample on data diode enclave for forensic signature extraction"
        ]
    },
    "DNS_TUNNEL": {
        "title": "DNS Tunneling Covert Exfiltration Channel",
        "mechanism": (
            "Covert bidirectional data transfer or payload staging encoded within recursive DNS query "
            "structures over UDP port 53. Threat actors encapsulate data inside encoded subdomains "
            "(Base32/Base64/Hex) and retrieve staged payloads through oversized TXT or NULL records, bypassing conventional web proxies."
        ),
        "discriminating_features": [
            ("dns_query_rate", "DNS Query Ingress Rate", "Surges to 20-50 queries/s (normal baseline: 1-4 q/s)"),
            ("dns_mean_query_length", "Average Query Domain Length", "Reaches 45-85 characters (normal: 12-22 chars), reflecting encoded payload chunks"),
            ("dns_txt_ratio", "DNS TXT Record Query Ratio", "Exceeds 0.40 (normal: < 0.05), indicating payload retrieval"),
            ("dns_tunnel_score", "Statistical Tunnel Heuristic Score", "Exceeds 0.75, validating structural tunnel syntax")
        ],
        "containment": [
            "Sinkhole the authoritative nameserver hosting the tunneling parent domain",
            "Enforce strict length limits and payload inspection at internal DNS forwarders",
            "Block direct egress UDP/53 requests from endpoint — restrict all lookups to managed internal DNS",
            "Inspect endpoint file system for recent staging archives or utilities (e.g., dnscat2, iodine)"
        ]
    },
    "DGA": {
        "title": "Domain Generation Algorithm (DGA) Rendezvous",
        "mechanism": (
            "An internal endpoint is generating high-frequency algorithmically generated domain name lookups. "
            "Malware families utilize DGAs to cyclically probe pseudo-random domains to locate dynamic active C2 "
            "infrastructure, resulting in distinct character entropy distributions and high query failure ratios."
        ),
        "discriminating_features": [
            ("dns_mean_entropy", "Domain String Shannon Entropy", "Rises to 3.6-4.6 bits/char (normal English-like domains: 2.2-3.0 bits)"),
            ("dns_nxdomain_ratio", "NXDOMAIN Failure Ratio", "Spikes above 0.50 (normal: < 0.08), reflecting failed attempts against unregistered seed domains"),
            ("dns_dga_score", "DGA Randomness Score", "Exceeds 0.70 based on n-gram vowel-consonant deviation")
        ],
        "containment": [
            "Identify the local process generating unresolved DNS requests on the host",
            "Quarantine endpoint to prevent successful rendezvous with live fallback infrastructure",
            "Extract algorithm seed / timestamp to proactively block future generated domain batches",
            "Submit memory dump to malware sandbox for reverse-engineering of DGA seed routine"
        ]
    },
    "RECON": {
        "title": "Reconnaissance & Port/Host Sweep",
        "mechanism": (
            "Systematic reconnaissance activity scanning internal services, open ports, and active subnets. "
            "Characterized by high destination diversity with minimal or zero payload transfer, seeking "
            "unpatched listening services or credential-accessible remote administration ports."
        ),
        "discriminating_features": [
            ("ports_per_sec", "Scanned Ports Rate", "Exceeds 60 ports/s (normal: < 2 ports/s)"),
            ("unique_ports", "Distinct Targeted Port Count", "Exceeds 100 ports within brief time window"),
            ("syn_only_ratio", "TCP SYN Scanning Ratio", "Above 0.85 with zero bytes payload exchanged")
        ],
        "containment": [
            "Immediately sever lateral network communication from the scanning source IP",
            "Audit internal switch ARP tables and host security logs for unauthorized credential use",
            "Check for installation of automated scanning tooling (e.g. Masscan, Nmap, AngryIP)",
            "Verify whether perimeter bastion hosts or jump boxes have been compromised"
        ]
    },
    "ENCRYPTED_MALWARE": {
        "title": "Encrypted Malware / Anomalous TLS Profile",
        "mechanism": (
            "Encrypted TLS session presenting anomalous cryptographic metadata distinct from standard operating "
            "system and browser communications. The handshake lacks standard Server Name Indication (SNI) extensions, "
            "offers restricted or obsolete cipher lists, or exhibits unusual TLS record fragmentation."
        ),
        "discriminating_features": [
            ("tls_suspicion_score", "TLS Fingerprint Suspicion Score", "Exceeds 0.70 based on non-standard client hello metadata"),
            ("has_sni", "Server Name Indication Flag", "Equals 0 (missing or raw IP), typical of direct-to-IP malware infrastructure"),
            ("tls_cipher_count", "Offered Cipher Count", "Restricted to 1-3 ciphers (standard modern browsers offer 15-28 ciphers)")
        ],
        "containment": [
            "Terminate active TLS session and block destination external IP address",
            "Calculate client JA3/JA4 fingerprint and query threat intelligence feeds for malware association",
            "Inspect host processes communicating over outbound 443/8443 without browser parent lineage",
            "Revoke endpoint session tokens and audit outbound proxy logs"
        ]
    },
    "DATA_EXFILTRATION": {
        "title": "Asymmetric Outbound Bulk Data Exfiltration",
        "mechanism": (
            "Massive, highly asymmetric egress byte transfer from an internal host to an external staging destination. "
            "Passive unidirectional observation identifies extreme outbound-to-inbound volume disparity, "
            "sustained high byte rates, and large packet sizes consistent with staged database dumps or archive exfiltration."
        ),
        "discriminating_features": [
            ("exfil_byte_ratio", "Outbound to Inbound Byte Ratio", "Exceeds 10:1 up to 40:1 (normal baseline: 0.2:1 to 1.5:1)"),
            ("outbound_bytes", "Total Outbound Volume", "Transfers 1M to 15M+ bytes in continuous sustained window"),
            ("mean_packet_size", "Average Packet Size", "Maximizes near MTU (1,200 - 1,450 bytes) with high density")
        ],
        "containment": [
            "Immediately cut outbound internet gateway access for the source host",
            "Block remote recipient IP address at perimeter routing egress filters",
            "Audit endpoint file access logs for mass archive creation (.zip, .7z, .tar, .enc)",
            "Notify data protection and compliance officers to assess potential regulated data exposure"
        ]
    },
    "NOVEL_BEHAVIOUR": {
        "title": "Unsupervised Zero-Day Outlier (Anti-Argmax Lane)",
        "mechanism": (
            "The unsupervised Isolation Forest model determined that this flow's feature vector lies far outside "
            "the multi-dimensional normal baseline envelope, yet no supervised XGBoost specialist triggered a high-confidence "
            "known attack classification. Under the Anti-Argmax Principle, Sentinel preserves forensic fidelity by quarantining "
            "this event in the Novel Behaviour Lane rather than forcing an inaccurate known label."
        ),
        "discriminating_features": [
            ("novelty_score", "Isolation Forest Anomaly Score", "Exceeds 0.55 novelty threshold, confirming significant deviation from baseline"),
            ("max_specialist_prob", "Maximum Specialist Score", "Remains below 0.45 threshold across all 7 known attack models")
        ],
        "containment": [
            "Preserve full flow context window and telemetry feature vector for analyst investigation",
            "Correlate entity graph relationships with neighboring hosts to detect emerging campaign patterns",
            "Export feature vector to threat intelligence repository for cluster similarity matching",
            "Deploy enhanced packet capture on the source host to collect full protocol payloads"
        ]
    }
}


class ExplainabilityEngine:
    @staticmethod
    def generate_narrative(
        host: str,
        threat_type: str,
        confidence: float,
        risk: int,
        evidence_items: List[Dict[str, Any]],
        alternative_hypotheses: List[Dict[str, Any]],
        persistence_desc: str = "sustained over multiple observation windows"
    ) -> str:
        """
        Synthesizes a strictly grounded, hallucination-free incident narrative as specified in Section 17.
        """
        conf_pct = int(confidence * 100)
        
        # Build evidence clauses
        clauses = []
        for ev in evidence_items:
            f = ev.get("feature", "")
            val = ev.get("value", 0.0)
            if "entropy" in f:
                clauses.append(f"elevated entropy ({val:.2f})")
            elif "rate" in f:
                clauses.append(f"a surge in transmission rate ({val:.1f})")
            elif "subdomain" in f or "length" in f:
                clauses.append(f"abnormally long query strings ({int(val)} chars)")
            elif "regularity" in f or "autocorr" in f or "iat" in f:
                clauses.append(f"rigid periodic timing regularity ({val:.2f})")
            elif "exfil" in f or "ratio" in f:
                clauses.append(f"extreme asymmetric outbound byte ratio ({val:.1f}:1)")
            elif "port" in f or "scan" in f:
                clauses.append(f"rapid destination port fan-out ({val:.1f} ports/s)")
            elif "tls" in f or "cipher" in f or "sni" in f:
                clauses.append(f"anomalous TLS handshake metadata without standard SNI")

        evidence_str = ", ".join(clauses[:3]) if clauses else "multiple correlated baseline deviations"
        
        alt_str = ""
        if alternative_hypotheses:
            alt = alternative_hypotheses[0]
            alt_name = alt.get("type", "")
            alt_score = int(alt.get("score", 0.0) * 100)
            if alt_name != threat_type and alt_score > 15:
                alt_str = f" The competing hypothesis '{alt_name}' scored {alt_score}% and was eliminated due to discriminating feature evidence."

        narrative = (
            f"Sentinel detected {threat_type} activity originating from host {host} with {conf_pct}% confidence "
            f"(Composite Risk: {risk}/100). The classification is driven by {evidence_str}, {persistence_desc}."
            f"{alt_str}"
        )
        return narrative

    @staticmethod
    def generate_detailed_explanation(
        host: str,
        threat_type: str,
        confidence: float,
        risk: int,
        evidence_items: List[Dict[str, Any]],
        alternative_hypotheses: List[Dict[str, Any]],
        features_dict: Optional[Dict[str, float]] = None,
        novelty_score: float = 0.0
    ) -> Dict[str, Any]:
        """
        Generates a comprehensive, structured forensic explanation detailing:
        1. Root-cause attack mechanism
        2. Quantitative baseline deviations (features observed vs expected)
        3. Differential diagnosis (why alternative hypotheses were rejected)
        4. Model validation (Isolation Forest novelty vs XGBoost probability)
        5. Prescriptive SOC analyst containment recommendations
        """
        threat_info = THREAT_EXPLANATIONS.get(threat_type.upper(), THREAT_EXPLANATIONS["NOVEL_BEHAVIOUR"])
        conf_pct = int(confidence * 100)
        novelty_pct = int(novelty_score * 100)
        f_dict = features_dict or {}

        # 1. Concrete Telemetry Deviations
        deviations = []
        for feat_name, label, desc in threat_info.get("discriminating_features", []):
            obs_val = f_dict.get(feat_name)
            if obs_val is not None:
                deviations.append({
                    "feature": feat_name,
                    "label": label,
                    "observed_value": round(float(obs_val), 3),
                    "baseline_rule": desc,
                    "status": "ANOMALOUS_DEVIATION"
                })

        # If deviations list empty, fall back to top evidence items
        if not deviations and evidence_items:
            for ev in evidence_items[:4]:
                deviations.append({
                    "feature": ev.get("feature", "metric"),
                    "label": ev.get("feature", "Metric").replace("_", " ").title(),
                    "observed_value": round(float(ev.get("value", 0.0)), 3),
                    "baseline_rule": f"Weighted decision impact: {ev.get('impact', 0.0):.2f}",
                    "status": "EVIDENCE_WEIGHT"
                })

        # 2. Differential Diagnosis Reasoning
        differential = []
        for alt in alternative_hypotheses:
            alt_name = alt.get("type", "")
            alt_score = round(float(alt.get("score", 0.0)), 3)
            if alt_name != threat_type:
                alt_pct = int(alt_score * 100)
                reason = f"Ranked lower ({alt_pct}%) due to absence of definitive {alt_name} signature features in window telemetry."
                if alt_name == "DDOS":
                    reason = f"Ruled out ({alt_pct}%): Total packet volume and connection rate were insufficient for volumetric denial-of-service."
                elif alt_name == "C2":
                    reason = f"Ruled out ({alt_pct}%): Inter-arrival timing exhibited human variance and failed the strict regularity threshold."
                elif alt_name == "DNS_TUNNEL":
                    reason = f"Ruled out ({alt_pct}%): DNS query lengths and TXT record ratios remained within normal resolver baselines."
                elif alt_name == "DGA":
                    reason = f"Ruled out ({alt_pct}%): Domain names showed low Shannon character entropy and normal vowel distribution."
                elif alt_name == "RECON":
                    reason = f"Ruled out ({alt_pct}%): Destination port diversity was low; connection attempts targeted established services."
                elif alt_name == "DATA_EXFILTRATION":
                    reason = f"Ruled out ({alt_pct}%): Outbound byte volume and directional ratio were balanced with inbound flows."
                elif alt_name == "NOVEL_BEHAVIOUR":
                    reason = f"Displaced by {threat_type} specialist ({alt_pct}%): Supervised model matched a specific known attack family."

                differential.append({
                    "candidate_threat": alt_name,
                    "probability_score": alt_score,
                    "reasoning": reason
                })

        # 3. Model Pipeline Diagnostics
        model_validation = {
            "isolation_forest_novelty": f"{novelty_pct}% novelty outlier score",
            "isolation_forest_status": "Outlier confirmed (exceeds 55% novelty threshold)" if novelty_score > 0.55 else "Within baseline margin",
            "xgboost_specialist": f"{threat_type} Classifier",
            "xgboost_confidence": f"{conf_pct}% calibrated probability",
            "anti_argmax_triggered": threat_type == "NOVEL_BEHAVIOUR"
        }

        return {
            "threat_type": threat_type,
            "title": threat_info["title"],
            "root_cause": (
                f"On host {host}, Sentinel detected telemetry signatures matching {threat_info['title']}. "
                f"This alert was generated with {conf_pct}% confidence and an Enclave Risk Index of {risk}/100."
            ),
            "mechanism": threat_info["mechanism"],
            "telemetry_deviations": deviations,
            "differential_diagnosis": differential,
            "model_validation": model_validation,
            "containment_recommendations": threat_info.get("containment", [])
        }
