import os
import time
import numpy as np
import pandas as pd

def generate_sentinel_hard_dataset(output_path: str = "data/sentinel_hard_dataset.csv"):
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    
    # Dynamic seed for fresh organic variations
    seed = int(time.time() * 1000) % (2**31)
    np.random.seed(seed)

    columns = [
        'duration', 'packets', 'bytes', 'packet_rate', 'byte_rate',
        'mean_packet_size', 'std_packet_size', 'mean_iat', 'std_iat',
        'cv_iat', 'autocorrelation_lag1', 'timing_regularity',
        'src_ip_entropy', 'dst_ip_entropy', 'dns_query_rate',
        'dns_mean_query_length', 'dns_mean_entropy', 'dns_txt_ratio',
        'dns_nxdomain_ratio', 'dns_dga_score', 'dns_tunnel_score',
        'has_tls', 'tls_cipher_count', 'has_sni', 'tls_suspicion_score',
        'hosts_per_sec', 'ports_per_sec', 'unique_destinations',
        'unique_ports', 'syn_only_ratio', 'vertical_scan_score',
        'horizontal_scan_score', 'exfil_byte_ratio', 'outbound_bytes',
        'label', 'class_name'
    ]

    # Challenging distributions: large benign background with subtle, stealthy threat injections
    distributions = {
        'benign': 6000,
        'ddos': 800,              # Low-rate pulsed / slowloris HTTP exhaustion
        'c2': 750,               # Jittered beaconing (randomized sleep, mimic human browsing)
        'dga': 750,              # Dictionary-blend / homograph DGA (low entropy words)
        'dns_tunnel': 750,       # Chunked low-throughput DNS exfiltration (short queries, low rate)
        'recon': 750,            # Low-and-slow vertical sweep (1 port per minute across random hosts)
        'encrypted_malware': 750,# Valid SNI forgery, TLS 1.3 mimicking legitimate CDNs
        'exfil': 750,            # Drip exfiltration (split into benign-looking cloud storage chunks)
        'novel_anomaly': 750     # Zero-day stealthy multi-vector anomaly
    }

    label_map = {
        'benign': 0,
        'ddos': 1,
        'c2': 2,
        'dga': 3,
        'dns_tunnel': 4,
        'recon': 5,
        'encrypted_malware': 6,
        'exfil': 7,
        'novel_anomaly': 8
    }

    rows = []

    def get_benign_features():
        duration = float(np.random.exponential(12.0) + 0.5)
        packets = int(np.random.lognormal(2.5, 1.2) + 2)
        bytes_val = int(packets * np.random.normal(520, 140))
        bytes_val = max(packets * 40, bytes_val)
        return {
            'duration': duration,
            'packets': packets,
            'bytes': bytes_val,
            'packet_rate': float(packets / max(0.1, duration)),
            'byte_rate': float(bytes_val / max(0.1, duration)),
            'mean_packet_size': float(bytes_val / max(1, packets)),
            'std_packet_size': float(np.random.uniform(20, 150)),
            'mean_iat': float(duration / max(1, packets)),
            'std_iat': float(np.random.exponential(0.6) + 0.1),
            'cv_iat': float(np.random.uniform(0.9, 2.5)),
            'autocorrelation_lag1': float(np.random.uniform(-0.15, 0.25)),
            'timing_regularity': float(np.random.uniform(0.05, 0.30)),
            'src_ip_entropy': float(np.random.uniform(0.2, 2.2)),
            'dst_ip_entropy': float(np.random.uniform(0.2, 2.2)),
            'dns_query_rate': float(np.random.exponential(0.8)),
            'dns_mean_query_length': float(np.random.normal(16, 4)),
            'dns_mean_entropy': float(np.random.uniform(1.8, 2.8)),
            'dns_txt_ratio': float(np.random.uniform(0.0, 0.04)),
            'dns_nxdomain_ratio': float(np.random.uniform(0.0, 0.06)),
            'dns_dga_score': float(np.random.uniform(0.02, 0.22)),
            'dns_tunnel_score': float(np.random.uniform(0.01, 0.15)),
            'has_tls': int(np.random.choice([0, 1], p=[0.25, 0.75])),
            'tls_cipher_count': int(np.random.choice([12, 16, 20, 24, 28])),
            'has_sni': 1,
            'tls_suspicion_score': float(np.random.uniform(0.02, 0.18)),
            'hosts_per_sec': float(np.random.exponential(0.4)),
            'ports_per_sec': float(np.random.exponential(0.4)),
            'unique_destinations': int(np.random.exponential(2) + 1),
            'unique_ports': int(np.random.exponential(2) + 1),
            'syn_only_ratio': float(np.random.uniform(0.01, 0.08)),
            'vertical_scan_score': float(np.random.uniform(0.01, 0.12)),
            'horizontal_scan_score': float(np.random.uniform(0.01, 0.12)),
            'exfil_byte_ratio': float(np.random.uniform(0.2, 1.6)),
            'outbound_bytes': int(np.random.lognormal(6.5, 1.2))
        }

    for class_name, count in distributions.items():
        for _ in range(count):
            feat = get_benign_features()
            feat['label'] = label_map[class_name]
            feat['class_name'] = class_name

            # Subtle, hard-to-track evasive modifications that sit right on boundary limits
            if class_name == 'ddos':
                # Stealthy Low-Rate / Pulsed Asymmetric DoS (Slowloris / Shrew attack)
                feat['packet_rate'] = float(np.random.uniform(95.0, 280.0))
                feat['byte_rate'] = float(np.random.uniform(18000.0, 85000.0))
                feat['src_ip_entropy'] = float(np.random.uniform(2.8, 4.4))
                feat['syn_only_ratio'] = float(np.random.uniform(0.48, 0.76))
                feat['duration'] = float(np.random.uniform(25.0, 120.0))
                feat['mean_packet_size'] = float(np.random.uniform(64.0, 180.0))

            elif class_name == 'c2':
                # Jittered C2 Beacon (Cobalt Strike / Sliver sleep jitter: 20-35% random perturbation)
                feat['cv_iat'] = float(np.random.uniform(0.20, 0.42))
                feat['autocorrelation_lag1'] = float(np.random.uniform(0.45, 0.72))
                feat['timing_regularity'] = float(np.random.uniform(0.55, 0.78))
                feat['packet_rate'] = float(np.random.uniform(1.2, 8.5))
                feat['packets'] = int(np.random.uniform(8, 40))

            elif class_name == 'dga':
                # Wordlist / Dictionary-based DGA (Suppenkasper / Matsnu style)
                feat['dns_mean_entropy'] = float(np.random.uniform(3.1, 3.85))
                feat['dns_nxdomain_ratio'] = float(np.random.uniform(0.32, 0.58))
                feat['dns_dga_score'] = float(np.random.uniform(0.52, 0.74))
                feat['dns_query_rate'] = float(np.random.uniform(1.8, 5.5))
                feat['dns_mean_query_length'] = float(np.random.uniform(22.0, 36.0))

            elif class_name == 'dns_tunnel':
                # Stealth Low-Throughput DNS Staging
                feat['dns_query_rate'] = float(np.random.uniform(2.5, 7.5))
                feat['dns_mean_query_length'] = float(np.random.uniform(28.0, 46.0))
                feat['dns_txt_ratio'] = float(np.random.uniform(0.18, 0.45))
                feat['dns_tunnel_score'] = float(np.random.uniform(0.54, 0.78))
                feat['dns_mean_entropy'] = float(np.random.uniform(2.9, 3.7))

            elif class_name == 'recon':
                # Low-and-Slow Stealth Host / Port Walk
                feat['ports_per_sec'] = float(np.random.uniform(3.5, 18.0))
                feat['hosts_per_sec'] = float(np.random.uniform(1.5, 6.0))
                feat['unique_ports'] = int(np.random.uniform(18, 95))
                feat['syn_only_ratio'] = float(np.random.uniform(0.42, 0.70))
                feat['vertical_scan_score'] = float(np.random.uniform(0.38, 0.68))
                feat['horizontal_scan_score'] = float(np.random.uniform(0.28, 0.58))

            elif class_name == 'encrypted_malware':
                # Malicious TLS session with forged legitimate SNI and modern ciphers
                feat['has_tls'] = 1
                feat['has_sni'] = 1
                feat['tls_cipher_count'] = int(np.random.choice([4, 6, 8, 10]))
                feat['tls_suspicion_score'] = float(np.random.uniform(0.48, 0.72))
                feat['timing_regularity'] = float(np.random.uniform(0.35, 0.60))

            elif class_name == 'exfil':
                # Trickle / Drip Exfiltration
                feat['exfil_byte_ratio'] = float(np.random.uniform(3.2, 7.5))
                feat['outbound_bytes'] = int(np.random.uniform(180000, 750000))
                feat['byte_rate'] = float(np.random.uniform(4000.0, 18000.0))
                feat['mean_packet_size'] = float(np.random.uniform(750.0, 1100.0))

            elif class_name == 'novel_anomaly':
                # Multi-dimensional subtle zero-day anomaly
                feat['packet_rate'] = float(np.random.uniform(45.0, 120.0))
                feat['cv_iat'] = float(np.random.uniform(0.38, 0.65))
                feat['timing_regularity'] = float(np.random.uniform(0.38, 0.62))
                feat['dns_mean_entropy'] = float(np.random.uniform(2.85, 3.45))
                feat['dns_query_rate'] = float(np.random.uniform(2.2, 5.0))
                feat['tls_suspicion_score'] = float(np.random.uniform(0.35, 0.58))
                feat['exfil_byte_ratio'] = float(np.random.uniform(2.2, 4.0))
                feat['outbound_bytes'] = int(np.random.uniform(90000, 320000))
                feat['src_ip_entropy'] = float(np.random.uniform(2.2, 3.6))

            rows.append(feat)

    df = pd.DataFrame(rows, columns=columns)
    df = df.sample(frac=1.0, random_state=seed).reset_index(drop=True)
    df.to_csv(output_path, index=False)
    return output_path

if __name__ == "__main__":
    generate_sentinel_hard_dataset()
