"""Shannon entropy, used to tell random-looking keys apart from normal words."""

from __future__ import annotations

import math
from collections import Counter


def shannon_entropy(value: str) -> float:
    """Return the entropy of ``value`` in bits per character.

    English words usually land around 2.5-3.5, while random API keys
    are typically above 4.
    """
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())
