"""
TLS and Encrypted Traffic Metadata Feature Extraction
Computes JA3/JA4 fingerprints, cipher suite counts, extension profiles, and packet sequence metadata
WITHOUT decrypting payloads (Section 9.6 & NTRO Constraint b).
"""

import hashlib
from typing import Dict, Any, List, Optional


def compute_ja3_fingerprint(
    tls_version: int,
    cipher_suites: List[int],
    extensions: List[int],
    elliptic_curves: List[int],
    ec_point_formats: List[int]
) -> Dict[str, str]:
    """
    Computes standard JA3 string and MD5 hash from TLS ClientHello fields:
    SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat
    """
    ciphers_str = "-".join(str(c) for c in cipher_suites)
    extensions_str = "-".join(str(e) for e in extensions)
    curves_str = "-".join(str(c) for c in elliptic_curves)
    points_str = "-".join(str(p) for p in ec_point_formats)

    ja3_string = f"{tls_version},{ciphers_str},{extensions_str},{curves_str},{points_str}"
    ja3_hash = hashlib.md5(ja3_string.encode('ascii')).hexdigest()

    return {
        "ja3_string": ja3_string,
        "ja3_hash": ja3_hash
    }


def extract_tls_metadata_features(
    client_hello: Optional[Dict[str, Any]],
    packet_sizes: List[int],
    duration: float
) -> Dict[str, float]:
    """
    Extracts numerical features from TLS handshake metadata and early packet-size sequences.
    """
    if not client_hello:
        return {
            "has_tls": 0.0,
            "tls_version": 0.0,
            "cipher_count": 0.0,
            "extension_count": 0.0,
            "has_sni": 0.0,
            "rare_cipher_ratio": 0.0,
            "early_seq_variance": 0.0,
            "tls_suspicion_score": 0.0,
        }

    tls_version = float(client_hello.get("version", 0x0303))
    ciphers = client_hello.get("ciphers", [])
    extensions = client_hello.get("extensions", [])
    sni = client_hello.get("sni", "")

    cipher_count = float(len(ciphers))
    extension_count = float(len(extensions))
    has_sni = 1.0 if sni else 0.0

    # Malware often omits SNI or presents very few (1-3) ciphers or antique SSLv3/TLS 1.0
    is_antique_version = 1.0 if tls_version in (0x0300, 0x0301) else 0.0
    rare_cipher_ratio = 1.0 if cipher_count < 3 or cipher_count > 45 else 0.0

    # Early packet-size sequence profile (first 10 packets)
    early_packets = packet_sizes[:10] if len(packet_sizes) >= 3 else []
    seq_variance = 0.0
    if len(early_packets) > 1:
        mean_p = sum(early_packets) / len(early_packets)
        seq_variance = sum((p - mean_p) ** 2 for p in early_packets) / len(early_packets)

    # Heuristic TLS anomaly score
    suspicion = 0.0
    if has_sni == 0.0:
        suspicion += 0.35  # encrypted outbound traffic without SNI is a strong indicator
    if is_antique_version:
        suspicion += 0.30
    if cipher_count < 4:
        suspicion += 0.20
    if duration > 10.0 and len(packet_sizes) < 10:
        suspicion += 0.15  # long-lived silent encrypted connection

    return {
        "has_tls": 1.0,
        "tls_version": float(tls_version),
        "cipher_count": cipher_count,
        "extension_count": extension_count,
        "has_sni": has_sni,
        "rare_cipher_ratio": rare_cipher_ratio,
        "early_seq_variance": round(seq_variance, 2),
        "tls_suspicion_score": round(min(1.0, suspicion), 3),
    }
