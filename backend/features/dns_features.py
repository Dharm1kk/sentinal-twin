"""
DNS and DGA Feature Extraction
Extracts query length, subdomain entropy, unique subdomains, TXT and NXDOMAIN ratios
as specified in Sentinel Feature Pipeline.
"""

from typing import List, Dict, Any, Optional
from .entropy_features import extract_dga_string_features, shannon_entropy


def analyze_dns_queries(
    queries: List[Dict[str, Any]],
    time_window: float = 5.0
) -> Dict[str, float]:
    """
    Analyzes a collection of DNS queries observed within an aggregation window.
    Each query dict contains: {'qname': str, 'qtype': str, 'rcode': int, 'timestamp': float}
    """
    total_queries = len(queries)
    if total_queries == 0:
        return {
            "query_rate": 0.0,
            "mean_query_length": 0.0,
            "max_query_length": 0.0,
            "mean_entropy": 0.0,
            "max_entropy": 0.0,
            "txt_ratio": 0.0,
            "nxdomain_ratio": 0.0,
            "unique_subdomain_ratio": 0.0,
            "dga_score": 0.0,
            "tunnel_indicator": 0.0,
        }

    effective_window = max(0.1, time_window)
    query_rate = total_queries / effective_window

    qnames = [q.get("qname", "") for q in queries]
    lengths = [len(qn) for qn in qnames]
    mean_length = sum(lengths) / total_queries
    max_length = max(lengths)

    # Entropies of the query strings
    entropies = [shannon_entropy(qn) for qn in qnames]
    mean_entropy = sum(entropies) / total_queries
    max_entropy = max(entropies)

    # TXT query ratio (DNS tunneling frequently uses TXT records to exfiltrate base64 payloads)
    txt_queries = sum(1 for q in queries if q.get("qtype") in ("TXT", 16, "16"))
    txt_ratio = txt_queries / total_queries

    # NXDOMAIN responses ratio (DGA generation generates many non-existent domain errors)
    nxdomains = sum(1 for q in queries if q.get("rcode") in (3, "NXDOMAIN"))
    nxdomain_ratio = nxdomains / total_queries

    # Unique subdomain prefixes
    subdomains = set()
    parent_domains = set()
    for qn in qnames:
        parts = qn.strip(".").split(".")
        if len(parts) >= 3:
            subdomains.add(parts[0])
            parent_domains.add(".".join(parts[-2:]))
        elif len(parts) >= 1:
            subdomains.add(parts[0])
            parent_domains.add(qn)
    
    unique_subdomain_ratio = len(subdomains) / total_queries

    # DGA vs DNS Tunnel indicators
    # DGA: high entropy, normal length, many NXDOMAINs, various parent domains
    # DNS Tunnel: extremely long subdomains (> 35 chars), repeated SAME parent domain, high query rate, TXT records
    is_same_parent = (len(parent_domains) == 1 and total_queries >= 3)
    
    tunnel_indicator = 0.0
    if mean_length > 35 or max_length > 50:
        tunnel_indicator += 0.35
    if max_entropy > 3.8:
        tunnel_indicator += 0.25
    if is_same_parent:
        tunnel_indicator += 0.20
    if txt_ratio > 0.2 or query_rate > 5.0:
        tunnel_indicator += 0.20

    dga_score = 0.0
    if mean_entropy > 3.5:
        dga_score += 0.35
    if nxdomain_ratio > 0.3:
        dga_score += 0.35
    if len(parent_domains) > 2:
        dga_score += 0.30

    return {
        "query_rate": round(float(query_rate), 2),
        "mean_query_length": round(float(mean_length), 2),
        "max_query_length": float(max_length),
        "mean_entropy": round(float(mean_entropy), 3),
        "max_entropy": round(float(max_entropy), 3),
        "txt_ratio": round(float(txt_ratio), 3),
        "nxdomain_ratio": round(float(nxdomain_ratio), 3),
        "unique_subdomain_ratio": round(float(unique_subdomain_ratio), 3),
        "dga_score": round(float(min(1.0, dga_score)), 3),
        "tunnel_indicator": round(float(min(1.0, tunnel_indicator)), 3),
    }
