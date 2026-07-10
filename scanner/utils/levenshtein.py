"""Levenshtein distance and token cosine similarity utilities."""

import re
from collections import Counter


def levenshtein(a: str, b: str) -> int:
    """Wagner-Fischer O(m*n) Levenshtein distance."""
    m, n = len(a), len(b)
    if m == 0:
        return n
    if n == 0:
        return m
    # Use two-row approach for space efficiency
    prev = list(range(n + 1))
    curr = [0] * (n + 1)
    for i in range(1, m + 1):
        curr[0] = i
        for j in range(1, n + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            curr[j] = min(
                prev[j] + 1,       # deletion
                curr[j - 1] + 1,   # insertion
                prev[j - 1] + cost  # substitution
            )
        prev, curr = curr, prev
    return prev[n]


def token_cosine_similarity(text_a: str, text_b: str) -> float:
    """Bag-of-words cosine similarity between two texts.

    Tokenizes using lowercase alphanumeric sequences.
    """
    tokens_a = re.findall(r'[a-z0-9]+', text_a.lower())
    tokens_b = re.findall(r'[a-z0-9]+', text_b.lower())
    if not tokens_a or not tokens_b:
        return 0.0
    counter_a = Counter(tokens_a)
    counter_b = Counter(tokens_b)
    # Dot product
    intersection = set(counter_a.keys()) & set(counter_b.keys())
    dot = sum(counter_a[t] * counter_b[t] for t in intersection)
    # Magnitudes
    mag_a = sum(v * v for v in counter_a.values()) ** 0.5
    mag_b = sum(v * v for v in counter_b.values()) ** 0.5
    if mag_a == 0 or mag_b == 0:
        return 0.0
    return dot / (mag_a * mag_b)
