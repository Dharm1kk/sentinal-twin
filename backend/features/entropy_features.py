"""
Entropy and String Distribution Features
Implements Shannon entropy, vowel/consonant ratio, digit ratios, and n-gram likelihoods
as specified in Sentinel Feature Pipeline.
"""

import math
from collections import Counter
from typing import Dict, Any, List

VOWELS = set("aeiouAEIOU")
CONSONANTS = set("bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ")

# Common English letter bigram frequencies baseline for DGA discrimination
COMMON_BIGRAMS = {
    "th": 0.0356, "he": 0.0307, "in": 0.0243, "er": 0.0205, "an": 0.0199,
    "re": 0.0185, "on": 0.0176, "at": 0.0149, "en": 0.0145, "nd": 0.0135,
    "ti": 0.0134, "es": 0.0134, "or": 0.0128, "te": 0.0120, "of": 0.0117,
    "ed": 0.0117, "is": 0.0113, "it": 0.0112, "al": 0.0109, "ar": 0.0107,
    "st": 0.0105, "to": 0.0107, "nt": 0.0104, "ng": 0.0095, "se": 0.0093,
    "ha": 0.0093, "as": 0.0087, "ou": 0.0087, "io": 0.0083, "le": 0.0083,
}


def shannon_entropy(data: str | List[Any]) -> float:
    """
    Computes Shannon entropy:
    H(X) = - sum( p(x) * log2(p(x)) )
    """
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def extract_dga_string_features(domain_or_subdomain: str) -> Dict[str, float]:
    """
    Extracts lexical features for DGA and DNS Tunnelling detection (Section 6).
    """
    s = domain_or_subdomain.strip().lower()
    # Strip trailing dot if present
    if s.endswith("."):
        s = s[:-1]
    
    length = len(s)
    if length == 0:
        return {
            "length": 0.0,
            "entropy": 0.0,
            "digit_ratio": 0.0,
            "vowel_consonant_ratio": 0.0,
            "unique_char_ratio": 0.0,
            "hyphen_count": 0.0,
            "ngram_likelihood": 0.0,
        }

    digits = sum(1 for c in s if c.isdigit())
    vowels = sum(1 for c in s if c in VOWELS)
    consonants = sum(1 for c in s if c in CONSONANTS)
    hyphens = s.count("-")
    unique_chars = len(set(s))

    entropy = shannon_entropy(s)
    digit_ratio = digits / length
    vc_ratio = vowels / max(1, consonants)
    unique_ratio = unique_chars / length

    # Bigram transition score
    ngram_score = 0.0
    if length >= 2:
        bigrams = [s[i:i+2] for i in range(length - 1)]
        match_count = sum(COMMON_BIGRAMS.get(bg, 0.0001) for bg in bigrams)
        ngram_score = match_count / len(bigrams)

    return {
        "length": float(length),
        "entropy": float(entropy),
        "digit_ratio": round(digit_ratio, 4),
        "vowel_consonant_ratio": round(vc_ratio, 4),
        "unique_char_ratio": round(unique_ratio, 4),
        "hyphen_count": float(hyphens),
        "ngram_likelihood": round(ngram_score, 4),
    }


def source_ip_entropy(ip_list: List[str]) -> float:
    """
    Computes Shannon entropy across a list of source IPs in a time window.
    High entropy indicates distributed spoofed flood; low entropy indicates targeted flood.
    """
    return shannon_entropy(ip_list)
