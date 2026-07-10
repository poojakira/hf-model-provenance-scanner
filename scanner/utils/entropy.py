"""Shannon entropy calculation for string/bytes data."""

import math
from collections import Counter

HIGH_ENTROPY_THRESHOLD = 5.7


def shannon_entropy(data) -> float:
    """Calculate Shannon entropy of a string or bytes sequence.

    Returns entropy in bits per character/byte.
    """
    if not data:
        return 0.0
    if isinstance(data, str):
        data = data.encode("utf-8", errors="replace")
    length = len(data)
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)
    return entropy
