import os
import time
import numpy as np
import pandas as pd

def generate_dataset(output_path: str = None) -> dict:
    if output_path is None:
        output_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../data/sentinel_dataset.csv'))

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    # Dynamic seed based on current timestamp so every generation produces fresh, real variations
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

    distributions = {
        'benign': 5000,
        'ddos': 1000,
        'c2': 800,
        'dga': 800,
        'dns_tunnel': 800,
        'recon': 800,
        'encrypted_malware': 800,
        'exfil': 800,
        'novel_anomaly': 600
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
        return {
            'duration': float(np.random.exponential(10)),
            'packets': int(np.random.lognormal(2, 1)),
            'bytes': int(np.random.lognormal(6, 1)),
            'packet_rate': float(np.random.exponential(10)),
            'byte_rate': float(np.random.exponential(100)),
            'mean_packet_size': float(np.random.normal(500, 100)),
            'std_packet_size': float(np.random.uniform(0, 100)),
            'mean_iat': float(np.random.exponential(0.5)),
            'std_iat': float(np.random.exponential(0.5)),
            'cv_iat': float(np.random.uniform(1.0, 3.0)),
            'autocorrelation_lag1': float(np.random.uniform(-0.1, 0.2)),
            'timing_regularity': float(np.random.uniform(0, 0.2)),
            'src_ip_entropy': float(np.random.uniform(0, 2)),
            'dst_ip_entropy': float(np.random.uniform(0, 2)),
            'dns_query_rate': float(np.random.exponential(0.5)),
            'dns_mean_query_length': float(np.random.normal(15, 5)),
            'dns_mean_entropy': float(np.random.uniform(1, 2.5)),
            'dns_txt_ratio': float(np.random.uniform(0, 0.05)),
            'dns_nxdomain_ratio': float(np.random.uniform(0, 0.05)),
            'dns_dga_score': float(np.random.uniform(0, 0.2)),
            'dns_tunnel_score': float(np.random.uniform(0, 0.1)),
            'has_tls': int(np.random.choice([0, 1], p=[0.8, 0.2])),
            'tls_cipher_count': int(np.random.choice([0, 1, 2, 3])),
            'has_sni': int(np.random.choice([0, 1], p=[0.5, 0.5])),
            'tls_suspicion_score': float(np.random.uniform(0, 0.2)),
            'hosts_per_sec': float(np.random.exponential(0.5)),
            'ports_per_sec': float(np.random.exponential(0.5)),
            'unique_destinations': int(np.random.exponential(2) + 1),
            'unique_ports': int(np.random.exponential(2) + 1),
            'syn_only_ratio': float(np.random.uniform(0, 0.1)),
            'vertical_scan_score': float(np.random.uniform(0, 0.1)),
            'horizontal_scan_score': float(np.random.uniform(0, 0.1)),
            'exfil_byte_ratio': float(np.random.uniform(0.1, 1.5)),
            'outbound_bytes': int(np.random.lognormal(5, 1))
        }

    for class_name, count in distributions.items():
        for _ in range(count):
            feat = get_benign_features()
            feat['label'] = label_map[class_name]
            feat['class_name'] = class_name
            
            if class_name == 'ddos':
                feat['packet_rate'] = float(np.random.uniform(800, 5000))
                feat['byte_rate'] = float(np.random.uniform(1e5, 1e7))
                feat['src_ip_entropy'] = float(np.random.uniform(4.5, 8))
                feat['syn_only_ratio'] = float(np.random.uniform(0.7, 0.99))
            elif class_name == 'c2':
                feat['cv_iat'] = float(np.random.uniform(0.01, 0.12))
                feat['autocorrelation_lag1'] = float(np.random.uniform(0.75, 0.98))
                feat['timing_regularity'] = float(np.random.uniform(0.80, 0.99))
            elif class_name == 'dga':
                feat['dns_mean_entropy'] = float(np.random.uniform(3.8, 4.7))
                feat['dns_nxdomain_ratio'] = float(np.random.uniform(0.50, 0.95))
                feat['dns_dga_score'] = float(np.random.uniform(0.75, 0.99))
            elif class_name == 'dns_tunnel':
                feat['dns_query_rate'] = float(np.random.uniform(10, 50))
                feat['dns_mean_query_length'] = float(np.random.uniform(45, 95))
                feat['dns_txt_ratio'] = float(np.random.uniform(0.4, 0.95))
                feat['dns_tunnel_score'] = float(np.random.uniform(0.8, 1.0))
            elif class_name == 'recon':
                feat['ports_per_sec'] = float(np.random.uniform(50, 500))
                feat['hosts_per_sec'] = float(np.random.uniform(10, 100))
                feat['unique_ports'] = int(np.random.uniform(50, 1000))
                feat['syn_only_ratio'] = float(np.random.uniform(0.80, 1.0))
            elif class_name == 'encrypted_malware':
                feat['has_tls'] = 1
                feat['tls_cipher_count'] = int(np.random.choice([1, 2, 3]))
                feat['has_sni'] = 0
                feat['tls_suspicion_score'] = float(np.random.uniform(0.70, 0.98))
            elif class_name == 'exfil':
                feat['exfil_byte_ratio'] = float(np.random.uniform(8.0, 50.0))
                feat['outbound_bytes'] = int(np.random.uniform(500000, 15000000))
            elif class_name == 'novel_anomaly':
                # Multivariate anomalous deviation outside known threat signatures
                feat['packet_rate'] = float(np.random.uniform(150, 350))
                feat['byte_rate'] = float(np.random.uniform(5000, 25000))
                feat['cv_iat'] = float(np.random.uniform(0.35, 0.75))
                feat['timing_regularity'] = float(np.random.uniform(0.35, 0.65))
                feat['dns_mean_entropy'] = float(np.random.uniform(3.0, 3.65))
                feat['dns_query_rate'] = float(np.random.uniform(3.0, 8.0))
                feat['dns_mean_query_length'] = float(np.random.uniform(30.0, 48.0))
                feat['tls_suspicion_score'] = float(np.random.uniform(0.40, 0.65))
                feat['exfil_byte_ratio'] = float(np.random.uniform(2.5, 4.8))
                feat['outbound_bytes'] = int(np.random.uniform(80000, 300000))
                feat['vertical_scan_score'] = float(np.random.uniform(0.25, 0.50))
                feat['src_ip_entropy'] = float(np.random.uniform(2.5, 4.0))
            
            rows.append(feat)
            
    df = pd.DataFrame(rows, columns=columns)
    
    # Shuffle the dataset so benign and all threat classes are chronologically interleaved
    df = df.sample(frac=1.0, random_state=seed).reset_index(drop=True)
    df.to_csv(output_path, index=False)
    
    class_dist = {str(k): int(v) for k, v in df['class_name'].value_counts().to_dict().items()}
    
    return {
        "path": output_path,
        "rows": len(df),
        "class_distribution": class_dist
    }


def generate_unlabelled_traffic(output_path: str = None) -> dict:
    """
    Generates a realistic stream of raw, unlabelled network flow features (34 canonical features).
    Contains strictly NO 'label' and NO 'class_name' columns.
    The Sentinel AI models must classify threats and anomalies autonomously.
    """
    if output_path is None:
        output_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../data/sentinel_unlabelled_traffic.csv'))

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    # Generate full dataset
    res = generate_dataset(output_path=output_path)
    df = pd.read_csv(output_path)

    # Strip out ground-truth columns to make it completely unlabelled
    feature_cols = [c for c in df.columns if c not in ['label', 'class_name']]
    unlabelled_df = df[feature_cols]

    unlabelled_df.to_csv(output_path, index=False)

    return {
        "path": output_path,
        "rows": len(unlabelled_df),
        "feature_count": len(feature_cols),
        "is_unlabelled": True
    }

